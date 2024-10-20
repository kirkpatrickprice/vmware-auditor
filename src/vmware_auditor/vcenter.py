#!/bin/python3

# vSphere API documentation available from https://developer.vmware.com/apis/968/vsphere

'''
Provides classes and basic functions for collecting security-related information from VMWare to assist in information security audits
'''

__author__='Randy Bartels <rjbartels [at] outlook.com>'


from getpass import getpass
from os import makedirs
from pathlib import Path
import argparse
import copy
import ssl
import sys

from pyVmomi import vim
from pyVim.connect import SmartConnect, Disconnect

from vmware_auditor import __version__
#import xlsxwriter

GLOBALS={
    'noAdvOptions': 'No advOptions found',
    'noAuthMethods': 'No authentication methods found',
    'noDisks': 'No disks attached',
    'noIssues': 'No issues found',
    'noNets': 'No networks configured',
    'noNtpServers': 'No NTP Servers configured',
    'noPortGroups': 'No portgroups found',
    'noSerialPorts': 'No serial ports found',
    'noServices': 'No services found',
    'noVMTools': 'VMTools unavailable',
}

class Results:
    '''
    Meta class used by other classes to override some common methods
    '''
    def __init__(self) -> None:
        pass

    def __str__(self):
        attrs = self.__dict__.keys()

        longestAttr=0
        for attr in attrs:
            if len(attr)>longestAttr:
                longestAttr=len(attr)

        txt=''
        for attr in attrs:
            txt+='{1:<{0}}: '.format(longestAttr,attr)
            content=getattr(self, attr)
            if isinstance (content, dict):
                # these are dictionaries of additional data
                longestKey=0
                for key in content.keys():
                    if len(key)>longestKey:
                        longestKey=len(key)
                
                index=0
                for key in content.keys():
                    if index==0:
                        spacing=0
                    else:
                        spacing=longestAttr+2
                    txt+=' '*spacing+'{1:<{0}}: {2}\n'.format(longestKey, key, content[key])
                    #print(f'%{spacing}s%-{longestKey}s: %s' % ('', key, content[key]))
                    index+=1
            elif isinstance(content, list) and isinstance(content[0], dict):
                # These are lists of dictionaries, so iterate through the list, and then through the dictionary
                longestKey=0
                for item in content:
                    for key in item.keys():
                        if len(key)>longestKey:
                            longestKey=len(key)
                index=0
                for item in content:
                    for key in item.keys():
                        if index==0:
                            spacing=0
                        else:
                            spacing=longestAttr+2
                        txt+=' '*spacing+'{1:<{0}}: {2}\n'.format(longestKey, key, item[key])
                        #print(f'%{spacing}s%-{longestKey}s: %s' % ('', key, item[key]))
                        index+=1

            else:
                txt+=str(content)+'\n'

        return txt

class EsxiHost(Results):
    def __init__(self, host: vim.HostSystem) -> None:
        '''
        Returns an ESXi Host instance populated with all of the data
        '''
        
        def _getAdvOptions(host):
            '''
            Returns the status of some interesting advanced configuration options on an ESXi host.
            '''
            results=[]
            interestingAdvOptions=[
                'Config.Defaults.security.host.ruissl',
                'Config.HostAgent.log.level',
                'Config.HostAgent.plugins.solo.enableMob',
                'Config.HostAgent.plugins.hostsvc.esxAdminsGroup',
                'DCUI.Access',
                'Mem.ShareForceSalting',
                'Net.DVFilterBindIpAddress',
                'Security.AccountLockFailures',
                'Security.AccountUnlockTime',
                'Security.PasswordHistory',
                'Security.PasswordMaxDays',
                'Security.PasswordQualityControl',
                'Security.SshSessionLimit',
                'Syslog.global.auditRecord.storageDirectory',
                'Syslog.global.auditRecord.remoteEnable',
                'Syslog.global.auditRecord.storageEnable',
                'Syslog.global.logDir',
                'Syslog.global.logHost',
                'Syslog.global.logLevel',
                'tools.setInfo.sizeLimit',
                'UserVars.DcuiTimeOut',
                'UserVars.ESXiShellInteractiveTimeOut',
                'UserVars.ESXiShellTimeOut',
                'UserVars.ESXiVPsAllowedCiphers'
                'UserVars.ESXiVPsDisabledProtocols',
                'UserVars.HostClientSessionTimeout',
            ]

            results=[{advOption.key: advOption.value} for advOption in host.configManager.advancedOption.setting if advOption.key in interestingAdvOptions]
            
            return results if len(results)>0 else GLOBALS['noAdvOptions']

        def _getAuthMethods(host):
            '''
            Returns the details for authentication methods supported on an ESXi host
            '''
            results=[]
            for authMethod in host.config.authenticationManagerInfo.authConfig:
                if isinstance(authMethod, vim.host.LocalAuthenticationInfo):
                    results.append({
                        'name': 'Local Auth',
                        'enabled': authMethod.enabled,
                    })
                elif isinstance(authMethod, vim.host.ActiveDirectoryInfo):
                    results.append({
                        'name': 'Active Directory integration',
                        'enabled': authMethod.enabled,
                        'domain': authMethod.joinedDomain,
                        'smartCardEnabled': authMethod.smartCardAuthenticationEnabled,
                        'trustedDomains': list(authMethod.trustedDomain),
                    })            
            
            return results if len(results)>1 else GLOBALS['noAuthMethods']

        def _getConfigIssues(host):
            '''
            Returns a list of configIssue items from the ESXi host
            '''
            results=[]
            results=[issue.fullFormattedMessage for issue in host.configIssue]

            return results if len(results)>0 else [GLOBALS['noIssues']]

        def _getPortGroupInfo(host):
            '''
            Returns details on the Port Groups enabled on an ESXi host
            '''
            results=[]
            for pg in host.config.network.portgroup:
                promMode=pg.spec.policy.security.allowPromiscuous
                macMode=pg.spec.policy.security.macChanges
                forgedMode=pg.spec.policy.security.forgedTransmits
                if not promMode: promMode='Inherit from vSwitch'
                if not macMode: macMode='Inherit from vSwitch'
                if not forgedMode: forgedMode='Inherit from vSwitch'
                results.append({
                    'name': pg.spec.name,
                    'vSwitchId': pg.vswitch.split('.')[-1],
                    'vlanId': pg.spec.vlanId,
                    'promiscuousMode': promMode,
                    'macChanges': macMode,
                    'forgedTransmits': forgedMode,
                    })

            return results if len(results)>0 else GLOBALS['noPortGroups']

        def _getNtpServerInfo(host: vim.HostSystem) -> list:
            '''
            Return a list of NTP servers configured for the ESXi host
            '''
            results=[]
            results=[item for item in host.config.dateTimeInfo.ntpConfig.server]

            return results if len(results)>0 else GLOBALS['noNtpServers']
        
        def _getServices(host):
            '''
            Returns the status for interesting services on an ESXi host
            '''
            results=[]
            interestingServices=[
                'TSM-SSH',
                'DCUI',
                'TSM',
                'attestd',
                'lwsmd',
                'ntpd',
                'ptpd',
                'snmpd',
                'vmsyslogd',
                'vpxa',
            ]
            for service in host.config.service.service:
                if service.key in interestingServices:
                    results.append({
                        'name': service.label,
                        'enabled': (service.policy == 'on'),
                        'running': service.running,
                        })
            
            return results if len(results)>0 else GLOBALS['noServices']

        self.name = host.name
        self.dataCenter = getParent(host.parent, vim.Datacenter)
        self.bios={
            'vendor': host.hardware.biosInfo.vendor,
            'version': host.hardware.biosInfo.biosVersion,
        }
        self.esxiVersion=host.config.product.fullName
        self.managementIP=host.summary.managementServerIp
        self.lockdownMode=host.config.lockdownMode
        self.cryptoState=host.runtime.cryptoState
        self.authMethods=_getAuthMethods(host)            
        self.issues=_getConfigIssues(host)
        self.ntpServers=_getNtpServerInfo(host)
        self.portGroups=_getPortGroupInfo(host)
        self.firewallDefaultPolicy={
            'incomingBlocked': host.config.firewall.defaultPolicy.incomingBlocked,
            'outgoingBlocked': host.config.firewall.defaultPolicy.outgoingBlocked,
        }
        self.services=_getServices(host)
        self.advOptions=_getAdvOptions(host)
        
class VirtualMachine(Results):
    def __init__(self, vCenterName: str, vm: vim.VirtualMachine,) -> None:
        '''
        Returns a virtual machine instance populated with all of the data
        '''

        def _getAllSnapshots(vm) -> list:
            '''
            Returns a list of all snapshots for a virtual machine
            '''
            results = []
            try:
                rootSnapshots = vm.snapshot.rootSnapshotList
            except:
                rootSnapshots = []

            for snapshot in rootSnapshots:
                results.append(snapshot)
                results += _getChildSnapshots(snapshot)

            return results

        def _getChildSnapshots(snapshot) -> list:
            '''
            Returns a (recursive) list of child snapshots
            '''
            results = []
            snapshots = snapshot.childSnapshotList

            for snapshot in snapshots:
                results.append(snapshot)
                results += _getChildSnapshots(snapshot)

            return results

        def _getCurrentSnapshotName(vm) -> str:
            '''
            Returns the name of the current snapshot (note: limited testing available, unsure if this work in a larger dataset)
            '''
            # I think this function will work consistently, but I didn't have a large enough data set available to be certain.
            try:
                key=vm.snapshot.currentSnapshot._moId
                snapshotList=_getAllSnapshots(vm)
                name=''
                for s in snapshotList:
                    if s.snapshot._moId == key:
                        name = s.name
                        break
            except Exception:
                name='Undetermined'
            
            return name

        def _getDisks(vm):
            results=[]
            for disk in vm.config.hardware.device:
                if isinstance(disk, vim.vm.device.VirtualDisk):
                    #Add a tuple with the label and size in GB
                    results.append({
                        disk.deviceInfo.label: str(round(disk.capacityInBytes/1024/1024/1024,2))+' GB'
                        })

            return results if len(results)>0 else GLOBALS['noDisks']

        def _getPortGroups(vm):
            results=[]
            if _VMGuestToolsActive(vm):
                if len(vm.network)==0:
                    results=GLOBALS['noNets']
                else:
                    for nic in vm.guest.net:
                        ipAddresses=[]
                        for address in nic.ipAddress:
                            ipAddresses.append(address)
                        results.append({
                            'name': nic.network,
                            'ipAddresses': ipAddresses,
                            'dhcp': nic.ipConfig.dhcp
                            })
            else:                
                if len(vm.network)==0:
                    results=GLOBALS['noNets']
                else:
                    for nic in vm.network:
                        results.append({
                            'name': nic.name,
                            'ipAddresses': GLOBALS['noVMTools'],
                            'dhcp': GLOBALS['noVMTools']
                            })
                    
            
            return results

        def _getSerialPorts(vm):
            results=[]
            for port in vm.config.hardware.device:
                if isinstance(port, vim.vm.device.VirtualSerialPort):                    
                    results.append({
                        port.deviceInfo.label: port.deviceInfo.summary
                        })

            return results if len(results)>0 else GLOBALS['noSerialPorts']

        def _getSnapshots(vm):
            results=[]
            if vm.snapshot is None:
                results = 'No snapshots'
            else:
                snapshotNames=[s.name for s in _getAllSnapshots(vm)]
                # snapshotNames=[]
                # for snapshot in snapshotList:
                #     snapshotNames.append(snapshot.name)
                results = {
                    'currentSnapshot': _getCurrentSnapshotName(vm),
                    'snapshotList': snapshotNames,
                } 

            return results   

        def _getToolsAdvConfig(vm) -> list:
            '''
            Returns the status of some interesting advanced configuration options on an ESXi host.
            '''
            results=[]
            interestingAdvOptions=[
                'isolation.device.connectable.disable',
                'isolation.device.edit.disable',
                'pciPassthru0.present',
                'pciPassthru1.present',
                'pciPassthru2.present',
                'pciPassthru3.present',
                'pciPassthru4.present',
                'pciPassthru5.present',
                'pciPassthru6.present',
                'pciPassthru7.present',
                'tools.guest.desktop.autolock',
                'tools.setInfo.sizeLimit',
                'RemoteDisplay.maxConnections',
            ]

            results=[{advOption.key: advOption.value} for advOption in vm.config.extraConfig if advOption.key in interestingAdvOptions]
            
            return results if len(results)>0 else [GLOBALS['noAdvOptions']]
        
        def _getVMGuestOS(vm) -> str:
            '''
            Returns the pretty name for the Guest Operating system from VM Tools
            '''

            return vm.guest.guestFullName if _VMGuestToolsActive(vm) else GLOBALS['noVMTools']
        
        def _getVMHostName(vm) -> str:
            '''
            Returns the guest's hostname derived from VMWare Tools
            '''

            return vm.guest.hostName if _VMGuestToolsActive(vm) else GLOBALS['noVMTools']

        def _VMGuestToolsActive(vm) -> bool:
                '''
                Returns the status of the Guest's VMWare Tools
                True = Includes both guestToolsExecutingScripts and guestToolsRunning
                False = guestToolsNotRunning or unknown
                '''

                
                return (vm.guest.toolsRunningStatus=='guestToolsExecutingScripts' or vm.guest.toolsRunningStatus=='guestToolsRunning')
            
        self.name=vm.name
        self.vCenter=vCenterName
        self.dataCenter=getParent(vm.parent, vim.Datacenter)
        self.esxiHostName=vm.runtime.host.name
        self.vmHostName=_getVMHostName(vm)
        self.guestOS=_getVMGuestOS(vm)
        self.powerState = vm.runtime.powerState
        self.CPUCount = vm.config.hardware.numCPU
        self.memorySizeMB = vm.config.hardware.memoryMB
        self.vmLogging=vm.config.flags.enableLogging
        self.faultTolerance=vm.config.flags.faultToleranceType
        self.syncTimeWithHost=vm.config.tools.syncTimeWithHost
        self.guestVMToolsInfo={
            'active': _VMGuestToolsActive(vm),
            'installType': vm.guest.toolsInstallType,
            'version': vm.guest.toolsVersion,
            'versionStatus': vm.guest.toolsVersionStatus2,
        }
        self.runVmToolsScripts={
            'afterPowerOn': vm.config.tools.afterPowerOn,
            'afterResume': vm.config.tools.afterResume,
            'beforeGuestReboot': vm.config.tools.beforeGuestReboot,
            'beforeGuestShutdown': vm.config.tools.beforeGuestShutdown,
            'beforeGuestStandby': vm.config.tools.beforeGuestStandby,
        }
        self.toolsAdvConfig=_getToolsAdvConfig(vm)
        self.changeTracking = {
            'enabled': vm.config.changeTrackingEnabled,
            'changeVersion': vm.config.changeVersion,
            'createDate': str(vm.config.createDate.month)+'/'+str(vm.config.createDate.day)+'/'+str(vm.config.createDate.year)
            }
        self.serialPorts=_getSerialPorts(vm)
        self.portGroups=_getPortGroups(vm)
        self.disks=_getDisks(vm)
        self.snapshots=_getSnapshots(vm)

def getEsxiHosts(hostFolder) -> list:
    '''
    Returns a list of ESXi hosts within a Data Center object
    '''
    results=[]
    
    for resource in hostFolder.childEntity:
        if isinstance(resource, vim.Folder):
            results+=getEsxiHosts(resource)
        elif isinstance(resource, vim.ComputeResource):
            for host in resource.host:
                results+=[host]

    return results

def getObjs(vimContent, vimType):
    '''
    Returns a list of objects that match vimType
    '''
    results=[]
    container = vimContent.viewManager.CreateContainerView(vimContent.rootFolder, vimType, True)
    for objectRef in container.view:
        results.append(objectRef)
    return results

def getParent(obj, vimType) -> str:
    if isinstance(obj, vimType):
        result=obj.name
    else:
        result=getParent(obj.parent, vimType)

    return result

def getVirtualMachines(vmFolder) -> list:
    '''
    Returns a list of virtual machines within a Data Center object
    '''
    results=[]
    
    for result in vmFolder.childEntity:
        if isinstance(result, vim.Folder):
            results+=getVirtualMachines(result)
        elif isinstance(result, vim.VirtualMachine):
            results+=[result]

    return results

def is_docker():
    # Taken from https://stackoverflow.com/questions/43878953/how-does-one-detect-if-one-is-running-within-a-docker-container-within-python
    cgroup = Path('/proc/self/cgroup')
    return Path('/.dockerenv').is_file() or cgroup.is_file() and 'docker' in cgroup.read_text()

def login (siConfig: dict) -> SmartConnect:
    '''
    Expects dict(host, user, pwd).  Returns a connected SmartConnect object
    '''
    loginSuccessful=False
    while not loginSuccessful:
        try:
            if not siConfig['host']:
                siConfig['host'] = input('vCenter Hostname: ')

            if not siConfig['user']:
                siConfig['user'] = input('vCenter Username: ')

            if not siConfig['pwd']:
                siConfig['pwd'] = getpass('vCenter Password: ')

            connect = SmartConnect(**siConfig)
            loginSuccessful=True
        except ssl.SSLCertVerificationError:
            # If the SSL connection fails because maybe a self-signed cert is used, tell SSL to forgo the cert validation and try again
            sslContext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) 
            sslContext.check_hostname = False
            sslContext.verify_mode = ssl.CERT_NONE
            siConfig['sslContext']=sslContext
        except vim.fault.InvalidLogin:
            print ('Invalid login credentials')
            print ('Connecting to: ', siConfig['host'])
            siConfig['user'] = None
            siConfig['pwd'] = None
        except KeyboardInterrupt:
            print('\n\nNo harm no foul...')
            sys.exit()
        except Exception as e:
            print ('General exception: ', str(e))
            sys.exit()
    return connect

def main():
    parser=argparse.ArgumentParser(
    prog=sys.argv[0].split('/')[-1],
    
    description='Connect to and display system details for a VMWare vCenter or individual ESXi host.'
    )
    parser.add_argument(
        '--host',
        dest='host',
        help='Hostname or IP address of the vCenter server or the ESXi host',
        metavar='HOSTNAME/IP',
    )
    parser.add_argument(
        '-u', '--user',
        dest='user',
        help='Username to login with',
        metavar='USERNAME',
    )
    parser.add_argument(
        '-p', '--password',
        dest='pwd',
        help='You really shouldn\'t use this, but if you insist... (default = user-prompted)',
        metavar='PASSWORD',
    )
    parser.add_argument(
        '-f', '--file',
        dest='filename',
        help='Override the results path/to/filename (default "./vmware_auditor/<hostname>.txt")',
        metavar="PATH/TO/FILENAME",
    )
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s v'+__version__,
    )

    siConfig=copy.deepcopy(vars(parser.parse_args()))

    # Set up the output file
    if siConfig['filename']:
        outfile = Path(str(siConfig['filename']))
    else:
        try:
            filename = siConfig['host']+'.txt'
        except TypeError:
            filename = input('Enter output filename (will be appended to "vmware_auditor\" folder): ')
        if is_docker():
            # Hard code the path the /results directory, which should be a mapped volume from the Docker run command line
            try:
                _ = input('Running in Docker.  Press ENTER to confirm that you mapped the /results directory in your "docker run -v /results:..." command or press CTRL-C to quit.')
            except KeyboardInterrupt:
                print('Use "docker run -v /results:. -ti --rm --network=host flyguy62n/vmware_auditor" to run the container')
                print('If you''d like to change the destination folder, change -v /results:<to-your-path>')
                sys.exit()
            outfile = Path('/results/vmware_auditor/{filename}')
        else:
            outfile = Path.cwd() / 'vmware_auditor' / filename
    
    try:
        print (f'Output results will be written to {outfile}.  Any existing file will be overwritten.\n')
        _ = input('Press ENTER to continue or CTRL-C to change the output file destination')
    except KeyboardInterrupt:
            print('\n\nNo harm no foul...')
            sys.exit()
    makedirs (str(outfile.absolute().parent), exist_ok=True)
    # Remove the 'filename' entry from the siConfig dictionary as it messes up pyvmomi login method
    del siConfig['filename']
    
    si=login(siConfig)
    # Blanking out the password now that we're logged in
    siConfig['pwd']=None
    content=si.RetrieveContent()


    # Get the data centers from vCenter
    dcs = getObjs(content, [vim.Datacenter])

    # Traverse the inventory and print VM configurations
    esxiResults=[]
    vmResults=[]

    for dc in dcs:
        for host in getEsxiHosts(dc.hostFolder):
            esxiResults.append(EsxiHost(host))

        for vm in getVirtualMachines(dc.vmFolder):
            vmResults.append(VirtualMachine(siConfig['host'], vm))


    # Get the results
    with open(outfile, 'w', encoding='utf-8') as f:
        
        for host in esxiResults:
            print(host)
            print(host, file=f)

        for vm in vmResults:
            print(vm)
            print(vm, file=f)
    
    # Disconnect from vCenter
    Disconnect(si)

if __name__=='__main__':
    main()
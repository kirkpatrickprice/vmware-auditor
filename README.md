# VMWare Auditor

Programs to help infosec professionals get useful information from a VMWare stack.  As of the first release, there is one tool:
    * vcenter.py -- Connects to a vCenter or ESXi server to provide information ESXi hosts and connected virtual machines

Information collected includes many items from the Center for Internet Security (CIS) VMWare ESXi v7 Benchmark.

# Running VMWare Auditor Tools
VMWare Auditor is delivered as:
* Python scripts for Linux, MacOS and other platforms where Python is already installed.  A recent version of Python should suffice -- it's been tested on Python 3.8 and later, but other v3 versions of Python might be OK
* Docker container at https://hub.docker.com/r/flyguy62n/vmware-auditor
* Windows ZIP file.  This includes a redistributable/embedded version of Python for Windows (v3.10.11) as well as the Python package dependencies.

See below for additional notes.

## What about OS-specific binaries?
An excellent question.  After many attempts, met with limited success, it appears that the VMWare-provided vSphere API Python modules don't appreciate the usual methods of creating packaged binaries (Pyinstaller, Py2exe et al).  Linux was mostly successful with the usual glibc version compatibility problems, but Windows was ... not.  So I decided to go the embedded Python version for Windows and to stick with native Python or Docker for Linux. 

If someone else has more success, please share!

# Python Scripts for Linux and MacOS
If you already have Python installed, this is a pretty easy way to run VMWare Auditor.  But, if you have Docker already at-hand, consider that method as it's literally one `docker run` command.

1.  `git clone https://github.com/flyguy62n/vmware-auditor` to make a local copy
2.  And then `python3 <toolname>.py -h` should do it.

Note: These are written in Python and will need some basic dependencies met.  See `requirements.txt`.  If you're familiar with installing Python modules using `pip`, you'll know what to do.  If you're not, see below for a [#crash-course-for-python-virtual-environments-and-installing-requirements](crash course) and a few commands to get you started (all commands assume Linux -- and probably Ubuntu, but they should work on MacOS too)

# Docker Container
From a functioning Docker environment:

`docker run -ti --rm --network=host flyguy62n/vmware-auditor`

NOTE: I have a Docker primer if you'd like a quick start to getting Docker working in Windows Subsystem for Linux.  Check out https://github.com/flyguy62n/docker-lab.  

# Windows ZIP
1.  Download the Windows ZIP file by clicking on the ZIP file above and then clicking on "Download" from that page.

    NOTE: DO NOT JUST RIGHT-CLICK ON THE ZIP FILE.  If you do, you'll be downloading an HTML file which is defeinitely NOT what you want.  

2.  Unzip to your favorite destination.
3.  Open a PowerShell or CMD prompt and change to the unzipped folder.
4.  Run the utilities with `.\python.exe <toolname>.py -h`

# Crash Course for Python Virtual Environments and Installing Requirements
After you create a clone (above), you'll probably want to create a virtual environment (VENV) to isolate this Python program from your system-wide Python modules and dependencies.  This isn't strictly required if you'll only ever run this one Python program as I'll do my best to keep dependencies from stepping on each other.  But, the bigger your library of Python-based awesomeness grows, the more likely it is that you'll run into conflicts.

1.  After cloning the repo to a local copy
    ```
    cd vmware-auditor/
    python -m venv .venv
    ```

2.  Now -- and everytime hereafter -- you'll need to `activate` your VENV...

    `source .venv/bin/activate`

    Notice that the prompt changes to show that you're in your VENV.
    
3.  Now, you'll probably need to update your PIP installer...

    `python3 -m pip install --upgrade pip`

4.  Next, you'll need to install the dependencies captured in the `requirements.txt` file.

    `python3 -m pip install -r requirements.txt`

5.  Finally, you can run the tools in this repo...
    `python3 <toolname>.py -h`

6.  When you're done, you can deactivate your VENV with

    `deactivate`

Just don't forget to reactivate it again when you need to run these tools again later

```
cd <path-to>/vmware-auditor
source .venv/bin/activate
./<run-some-tools>.py
```
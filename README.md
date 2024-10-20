# VMWare Auditor

Programs to help infosec professionals get useful information from a VMWare stack.  As of the first release, there is one tool:
* vcenter.py -- Connects to a vCenter or ESXi server to provide information ESXi hosts and connected virtual machines

Information collected includes many items from the Center for Internet Security (CIS) VMWare ESXi v7 Benchmark.

# Running VMWare Auditor Tools
VMWare Auditor is delivered as:
* Python scripts for Linux, MacOS and other platforms where Python is already installed.  A recent version of Python should suffice -- it's been tested on Python 3.8 and later, but other v3 versions of Python might be OK
* Docker container at https://hub.docker.com/r/flyguy62n/vmware-auditor
* OS-specific [https://github.com/kirkpatrickprice/vmware-auditor/releases](releases)

See below for additional notes.

## What about OS-specific binaries?
See [https://github.com/kirkpatrickprice/vmware-auditor/releases](releases)

# Python is Already Available
If you already have Python installed, this is the easiest way to run VMWare Auditor.  

1. (Recommended) Create a Python virtual environment to isolate this from any other Python apps on your system.

MacOS and Linux
```
python3 -m venv .venv-vmware
source .venv-vmware/bin/activate
```

Windows
```
py -m venv .venv-vmware
bin/Scripts/activate
```

2. Install VMWare Auditor from PyPI
```
pip install vmware_auditor
```

This will also create an OS-specific executable link to `vcenter.py` and place it on your path.

3. Run VMWare Auditor
```
vcenter --help
```

The results will be saved in the current folder as `vmware_auditor\<hostname>.txt` or to the path\to\filename you provide with `-f`.  If you don't provide the `--host` paramter on the command line, it will prompt you for a filename to use instead, which will be written to the `vmware_auditor\` folder.

4. When you're done, either just close the command prompt window or deactivate the Python virtual environment if you still need the window for other things:
```
deactivate
```

5. You can run it again at another time by changing to the directory where you created the virtual environment and activating it again with the OS-specific activation command from Step #1 above.

# Docker Container
From a functioning Docker environment:

`docker run -v /results:. -ti --rm --network=host flyguy62n/vmware-auditor`

NOTES:
* The `-v /results:.` is important for the output file.  The program detects if it's running inside a Docker container and writes the results to `/results`.  If you're not familiar with Docker, the `-v` maps the `/results` directory inside the container to your current directory (`.`) outside the container.  
* You can change where you'd like to save the results by changing the path on the right side of the `:` (e.g. `-v /results:/home/jdoe/vmware-auditor` or any other destination on your filesystem), but **always** leave the `/results` part unchanged.
* I have a Docker primer if you'd like a quick start to getting Docker working in Windows Subsystem for Linux.  Check out [https://github.com/flyguy62n/docker-lab](Docker Lab).


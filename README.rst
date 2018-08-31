.. image:: https://github.com/rastrea2r/rastrea2r/blob/master/logo.png
   :align: center
   :alt: logo

.. image:: https://travis-ci.org/rastrea2r/rastrea2r.svg?branch=master
   :target: https://travis-ci.org/rastrea2r/rastrea2r.svg?branch=master
   :alt: travis-ci for master branch

.. image:: https://readthedocs.org/projects/rastrea2r/badge/?version=latest
   :target: http://rastrea2r.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status

.. image:: http://www.repostatus.org/badges/1.1.0/active.svg
   :alt: Project Status: Active - The project has reached a stable, usable state and is being actively developed.
   :target: http://www.repostatus.org/#active

.. image:: https://github.com/toolswatch/badges/blob/master/arsenal/usa/2018.svg
   :alt: Black Hat Arsenal 2018
   :target: https://www.blackhat.com/us-18/arsenal/schedule/index.html#rastrea2r-reloaded-collecting-38-hunting-for-iocs-with-gusto-and-style-12103

Description
-----------

Ever wanted to turn your AV console into an Incident Response & Threat Hunting machine? Rastrea2r (pronounced "rastreador" - hunter- in Spanish) is a multi-platform open source tool that allows incident responders and SOC analysts to triage suspect systems and hunt for Indicators of Compromise (IOCs) across thousands of endpoints in minutes. To parse and collect artifacts of interest from remote systems (including memory dumps), rastrea2r can execute sysinternal, system commands and other 3rd party tools (including the custom scripts) across multiples endpoints, saving the output to a centralized share for automated or manual analysis. By using a client/server RESTful API, rastrea2r can also hunt for IOCs on disk and memory across multiple systems using YARA rules. As a command line tool, rastrea2r can be easily integrated within McAfee ePO, as well as other AV consoles and orchestration tools, allowing incident responders and SOC analysts to collect forensic evidence and hunt for IOCs without the need for an additional agent, with 'gusto' and style!


Currently Supported functionalities
-----------------------------------

- Fast Triaging: Execute Sysinternals tools, or any other 3rd party batch scripts (including custom scripts) to perform basic triaging ** Windows Only
- Forensic Artifact Collection: Capabilities to Create snapshots quickly (Implements a wrapper for CyLR tool, which collects forensic artifacts from hosts with NTFS file systems quickly, securely and minimizes impact to the host.) **Windows Only
- Web History: Collect the Browser History (Currently supports IE, Chrome, Firefox only) ** 
- Prefetch Tool: Collect the prefetch data in Windows as they are great artifacts for forensic investigations to analyze applications that have been run on a system. ** Windows only
- Memory Dump: Acquires a memory dump from the endpoint ** Windows only
- Yara Disk: Yara scan for file/directory objects on disk
- Yara Mem: Yara scan for running processes in memory

Rastrea2r now also supports pushing the Scan Results to a Restful Server using HTTP. This functionality allows the users to deploy rastrea2r on their enterprises so that they can execute different rastrea2r commands to collect and triage the data and later store the Yara disk or Yara Mem results onto the Server for further analysis.

A high level design of the rastrea2r deployment on end points can be seen as below:

.. image:: https://github.com/rastrea2r/rastrea2r/blob/master/docs/images/Deploy_Rastrea2r.png
    :width: 200px
    :align: center
    :height: 100px
    :alt: Rastrea2r end point deployment

Rastrea2r allows users to specify the list of commands or batch scripts to be executed during "triage" via a configuration file, which is located `here
<https://github.com/rastrea2r/rastrea2r/blob/master/src/rastrea2r/rastrea2r.ini>`_.


*Notes*

For memdump and triage modules, SMB shares must be set up in this specific way:

* Binaries (sysinternals, batch files and others) must be located in a shared folder called TOOLS (read only)

      \\path-to-share-foldertools

* Output is sent to a shared folder called DATA (write only)

     \\path-to-share-folderdata

* For yara-mem and yara-disk scans, the yara rules must be present in the rastrea2r server before using the commands


Dependencies
------------
* yara-python==3.7.0
* psutil==5.4.6
* Requests=2.19.1
* Pyinstaller=3.3.1

Quickstart
----------

* Clone the project to your local directory (or download the zip file of the project)

.. code-block:: console

    $git clone https://github.com/rastrea2r/rastrea2r.git
    $cd rastrea2r

* All the dependencies necessary for the tool to run can be installed within a virtual environment via the provided makefile.

.. code-block:: console

    $make help
    help                           - display this makefile's help information
    venv                           - create a virtual environment for development
    clean                          - clean all files using .gitignore rules
    scrub                          - clean all files, even untracked files
    test                           - run tests
    test-verbose                   - run tests [verbosely]
    check-coverage                 - perform test coverage checks
    check-style                    - perform pep8 check
    fix-style                      - perform check with autopep8 fixes
    docs                           - generate project documentation
    check-docs                     - quick check docs consistency
    serve-docs                     - serve project html documentation
    dist                           - create a wheel distribution package
    dist-test                      - test a wheel distribution package
    dist-upload                    - upload a wheel distribution package

* Create a virtual environment with all dependencies

.. code-block:: console

    $make venv
    //Upon successful creation of the virtualenvironment, enter the virtualenvironment as instructed, for ex:
    $source /Users/ssbhat/.venvs/rastrea2r/bin/activate


* Start the rastrea2r server by referring to: https://rastrea2r-server.readthedocs.io/en/latest/?badge=latest


* Now execute the client program, depending on which platform you are trying to scan choose the target python script appropriately. Currently Windows, Linux and Mac platforms are supported.




.. note:: Following instructions explain the steps on a Windows, but on Mac and linux the steps should follow the same except that you would execute the client from the specified platform folder.
          On Windows PC's, make file system is not supported and if you need to execute rastrea2r client then you need to create the virtualenvironment manually and install the dependencies on it
          using pip install -r requirements.txt.

.. code-block:: console

   $python rastrea2r_windows.py -h
   usage: rastrea2r_windows.py [-h] [-v] {yara-disk,yara-mem,triage,memdump,triage,web-hist,prefetch} ...

   Rastrea2r RESTful remote Yara/Triage tool for Incident Responders

   positional arguments:  {yara-disk,yara-mem,triage,memdump,triage,web-hist,prefetch}

   modes of operation
    yara-disk           Yara scan for file/directory objects on disk
    yara-mem            Yara scan for running processes in memory
    memdump             Acquires a memory dump from the endpoint
    triage              Collect triage information from endpoint
    web-hist            Generates web history for specified user account
    prefetch            Generates prefetch view
    collect             Acquires artifacts from the endpoint


   optional arguments:
    -h, --help            show this help message and exit
    -v, --version         show program's version number and exit


   Further more, the available options under each command can be viewed by executing the help option. i,e

   $python rastrea2r_windows.py yara-disk -h
   usage: rastrea2r_osx.py yara-disk [-h] [-s] path server rule

   positional arguments:
   path          File or directory path to scan
   server        rastrea2r REST server
   rule          Yara rule on REST server

   optional arguments:
   -h, --help    show this help message and exit
   -s, --silent  Suppresses standard output


* For ex, on a Mac system you would do:

.. code-block:: console

   $cd src/rastrea2r/windows/

   $python rastrea2r_windows.py yara-disk /opt http://localhost example.yara


Executing rastrea2r.exe on Windows
----------------------------------

* On windows platform rastrea2r can be compiled into a single exe file so that it can later be executed on the endpoints. To do so, execute the build_exe.bat file located under "src" folder so that it can generate the exe from the latest codebase. Upon successful execution it will generate the exe under dist folder. And all the functionalities of rastrea2r described above can be executed with exe as well. for ex:

.. code-block:: console

    $rastrea2r.exe collect tools.myserver.com data.myserver.com   

    //where tools.myserver.com has a shared smb folder called "tools" with readonly access as all the tools specified in the rastrea2r.ini must be present in this tools folder prior to executing the commands 
    //      data.myserver.com is server which has shared folder called "data" with write access so that all the results from the rastrea2r command can be placed here.


.. note:: 
    In order to generate the rastrea2r.exe the build_exe.bat internally uses pyinstaller spec file. Which would have a dependency on the Windows C++ binaries which must be installed on the machine prior to calling the build_exe.bat. Follow these instructions to update the spec file.

.. code-block:: console

    1. Download and install this Windows SDK: https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk
    2. These dlls can then be found here (or Program Files x86):
        C:\Program Files\Windows Kits\10\Redist\ucrt\DLLs
    3. Update your pathex variable in your spec file to tell pyinstaller to look there:
        
        pathex=['C:\\Users\\grey_hat\\Desktop\\csm\\test', 
            'C:\\Program Files (x86)\\Windows Kits\\10\\Redist\\ucrt\\DLLs\\x86',
            'C:\\Program Files (x86)\\Windows Kits\\10\\Redist\\ucrt\\DLLs\\x64']



Report Bugs
===========

Report bugs at the `issue tracker <https://github.com/ssbhat/rastrea2r/issues>`_.

Please include:

  - Operating system name and version.
  - Any details about your local setup that might be helpful in troubleshooting.
  - Detailed steps to reproduce the bug.



Contributing to rastrea2r project
---------------------------------

The `Developer Documentation <http://rastrea2r.readthedocs.io>`_ provides complete information on how to contribute to rastrea2r project


Demo videos on Youtube
----------------------
* Video 1: Incident Response / Triage with rastrea2r on the command line - https://youtu.be/uFIZxqWeSyQ

* Video 2: Remote Yara scans with rastrea2r on the command line - https://youtu.be/cnY1yEslirw

* Video 3: Using rastrea2r with McAfee ePO - Client Tasks & Execution - https://youtu.be/jB17uLtu45Y


Presentations
-------------
* `rastrea2r at BlackHat Arsenal 2018 <https://www.blackhat.com/us-18/arsenal/schedule/#rastrea2r-reloaded-collecting-38-hunting-for-iocs-with-gusto-and-style-12103>`_.
* `rastrea2r at BlackHat Arsenal 2016 <https://www.blackhat.com/us-16/arsenal.html#rastrea2r`_.
* `Recording of talk on rastrea2r at the SANS Threat Hunting Summit 2016 <https://www.youtube.com/watch?v=0PvBsL6KKfA&feature=youtu.be&a`_.
* `SANS SOC Summit 2017<https://www.sans.org/summit-archives/file/summit-archive-1496771906.pdf>`_.
* `SANS SIEM Summit 2017<https://www.sans.org/summit-archives/file/summit-archive-1511996504.pdf>`_.

Publications and Articles
-------------------------
* `Helping Overburdened SOC Analysts Become More Effective Threat Hunters<https://securingtomorrow.mcafee.com/technical-how-to/helping-overburdened-soc-analysts-become-effective-threat-hunters>`_.

Credits & References
--------------------

* To Robert Gresham Jr. (@rwgresham) and Ryan O'Connor (@_remixed) for their contributions to the Triage module. Thanks folks!

* To Ricardo Dias for the idea of using a REST server and his great paper on how to use Python and Yara with McAfee ePO: http://www.sans.org/reading-room/whitepapers/forensics/intelligence-driven-incident-response-yara-35542

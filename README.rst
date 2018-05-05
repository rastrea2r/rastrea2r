.. image:: https://github.com/rastrea2r/rastrea2r/blob/master/logo.png
:target: https://github.com/rastrea2r/rastrea2r/blob/master/logo.png

rastrea2r
#########
**Collecting & Hunting for Indicators of Compromise (IOC) with gusto and style!!!**

.. image:: https://travis-ci.org/rastrea2r/rastrea2r.svg?branch=master
:target: https://travis-ci.org/rastrea2r/rastrea2r.svg?branch=master


Description
-----------

    Ever wanted to turn your AV console into an Incident Response & Threat Hunting machine? Rastrea2r (pronounced "rastreador" - hunter- in Spanish) is a multi-platform open source tool that allows incident responders and SOC analysts to triage suspect systems and hunt for Indicators of Compromise (IOCs) across thousands of endpoints in minutes. To parse and collect artifacts of interest from remote systems (including memory dumps), rastrea2r can execute sysinternal, system commands and other 3rd party tools across multiples endpoints, saving the output to a centralized share for automated or manual analysis. By using a client/server RESTful API, rastrea2r can also hunt for IOCs on disk and memory across multiple systems using YARA rules. As a command line tool, rastrea2r can be easily integrated within McAfee ePO, as well as other AV consoles and orchestration tools, allowing incident responders and SOC analysts to collect forensic evidence and hunt for IOCs without the need for an additional agent, with 'gusto' and style!


Dependencies
------------
  * Python 2.7.x
  * git
  * bottle
  * requests
  * yara-python
  *


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


* Start the rastrea2r server by going to $PROJECT_HOME/src/rastrea2r/server folder


Executing rastrea2r on Windows
------------------------------

   * Apart from the libraries specified in requirements.txt, we need to install the following libraries

      * PSutil for win64: https://github.com/giampaolo/psutil

      * WMI for win32: https://pypi.python.org/pypi/WMI/

      * Requests: pip install requests

   * Compiling rastrea2r
       Make sure you have all the dependencies installed for the binary you are going to build on your Windows box. Then install:

       * Pywin32: http://sourceforge.net/projects/pywin32/files/ ** Windows only

       * Pyinstaller: https://github.com/pyinstaller/pyinstaller/wiki


Currently Supported functionality
---------------------------------

     * yara-disk: Yara scan for file/directory objects on disk

     * yara-mem: Yara scan for running processes in memory

     * memdump: Acquires a memory dump from the endpoint ** Windows only

     * triage: Collects triage information from the endpoint ** Windows only

Notes
-----

    For memdump and triage modules, SMB shares must be set up in this specific way:

    * Binaries (sysinternals, batch files and others) must be located in a shared folder called TOOLS (read only)

      \\path-to-share-foldertools

    * Output is sent to a shared folder called DATA (write only)

     \\path-to-share-folderdata

    * For yara-mem and yara-disk scans, the yara rules must be in the same directory where the server is executed from.

    * The RESTful API server stores data received in a file called results.txt in the same directory.



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

    * rastrea2r at BlackHat Arsenal 2016 (check PDF for documentation on usage and examples) https://www.blackhat.com/us-16/arsenal.html#rastrea2r
       https://github.com/aboutsecurity/Talks-and-Presentations/blob/master/Ismael_Valenzuela-Hunting_for_IOCs_rastrea2r-BH_Arsenal_2016.pdf

    * Recording of talk on rastrea2r at the SANS Threat Hunting Summit 2016
       https://www.youtube.com/watch?v=0PvBsL6KKfA&feature=youtu.be&a

Credits & References
--------------------
    * To Robert Gresham Jr. (@rwgresham) and Ryan O'Connor (@_remixed) for their contributions to the Triage module. Thanks folks!

    * To Ricardo Dias for the idea of using a REST server and his great paper on how to use Python and Yara with McAfee ePO: http://www.sans.org/reading-room/whitepapers/forensics/intelligence-driven-incident-response-yara-35542







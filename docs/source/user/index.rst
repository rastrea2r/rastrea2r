User Guide
##########

This section of the documentation provides user focused information such as
installing and quickly using this package.

.. _install-guide-label:

Install Guide
=============

Dependencies
------------
* Python 2.7.x
* git
* bottle
* requests
* yara-python


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

.. code-block:: console

   $cd src/rastrea2r/server/
   $python rastrea2r_server_v0.3.py
   Bottle v0.12.13 server starting up (using WSGIRefServer())...
   Listening on http://0.0.0.0:8080/

* Now execute the client program, depending on which platform you are trying to scan choose the target python script appropriately. Currently Windows, Linux and Mac platforms are supported.

.. code-block:: console

   $python rastrea2r_osx_v0.3.py -h
   usage: rastrea2r_osx_v0.3.py [-h] [-v] {yara-disk,yara-mem,triage} ...

   Rastrea2r RESTful remote Yara/Triage tool for Incident Responders

   positional arguments:  {yara-disk,yara-mem,triage}

   modes of operation
    yara-disk           Yara scan for file/directory objects on disk
    yara-mem            Yara scan for running processes in memory
    triage              Collect triage information from endpoint

   optional arguments:
    -h, --help            show this help message and exit
    -v, --version         show program's version number and exit


   Further more, the available options under each command can be viewed by executing the help option. i,e

   $python rastrea2r_osx_v0.3.py yara-disk -h
   usage: rastrea2r_osx_v0.3.py yara-disk [-h] [-s] path server rule

   positional arguments:
   path          File or directory path to scan
   server        rastrea2r REST server
   rule          Yara rule on REST server

   optional arguments:
   -h, --help    show this help message and exit
   -s, --silent  Suppresses standard output


* For ex, on a Mac or Unix system you would do:

.. code-block:: console

   $cd src/rastrea2r/osx/

   $python rastrea2r_osx_v0.3.py yara-disk /opt http://127.0.0.1:8080/ test.yar


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

Report Bugs
===========

Report bugs at the `issue tracker <https://github.com/ssbhat/rastrea2r/issues>`_.

Please include:

  - Operating system name and version.
  - Any details about your local setup that might be helpful in troubleshooting.
  - Detailed steps to reproduce the bug.

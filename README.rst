rastrea2r https://travis-ci.org/rastrea2r/rastrea2r.svg?branch=master
#########

rastrea2r

Collecting & Hunting for Indicators of Compromise (IOC) with gusto and style! by @aboutsecurity

Ever wanted to turn your AV console into an Incident Response & Threat Hunting machine? Rastrea2r (pronounced "rastreador" - hunter- in Spanish) is a multi-platform open source tool that allows incident responders and SOC analysts to triage suspect systems and hunt for Indicators of Compromise (IOCs) across thousands of endpoints in minutes. To parse and collect artifacts of interest from remote systems (including memory dumps), rastrea2r can execute sysinternal, system commands and other 3rd party tools across multiples endpoints, saving the output to a centralized share for automated or manual analysis. By using a client/server RESTful API, rastrea2r can also hunt for IOCs on disk and memory across multiple systems using YARA rules. As a command line tool, rastrea2r can be easily integrated within McAfee ePO, as well as other AV consoles and orchestration tools, allowing incident responders and SOC analysts to collect forensics evidence and hunt for IOCs without the need for an additional agent, with 'gusto' and style!


Quickstart
==========

rastrea2r is available on PyPI and can be installed with `pip <https://pip.pypa.io>`_.

.. code-block:: console

    $ pip install rastrea2r

After installing rastrea2r you can use it like any other Python module.

Here is a simple example:

.. code-block:: python

    # TODO
    # Fill this section in with the common use-case.

The `API Reference <http://rastrea2r.readthedocs.io>`_ provides API-level documentation.


Demo videos on Youtube
Video 1: Incident Response / Triage with rastrea2r on the command line - https://youtu.be/uFIZxqWeSyQ

Video 2: Remote Yara scans with rastrea2r on the command line - https://youtu.be/cnY1yEslirw

Video 3: Using rastrea2r with McAfee ePO - Client Tasks & Execution - https://youtu.be/jB17uLtu45Y

rastrea2r at BlackHat Arsenal 2016 (check PDF for documentation on usage and examples)
https://www.blackhat.com/us-16/arsenal.html#rastrea2r

https://github.com/aboutsecurity/Talks-and-Presentations/blob/master/Ismael_Valenzuela-Hunting_for_IOCs_rastrea2r-BH_Arsenal_2016.pdf

Recording of my talk on rastrea2r at the SANS Threat Hunting Summit 2016
https://www.youtube.com/watch?v=0PvBsL6KKfA&feature=youtu.be&a

Dependencies
** General

Python 2.7.x

https://www.python.org/

** Server.py

Bottle: pip install bottle

** Client

Yara: latest yara-python from Google code (https://plusvic.github.io/yara/)

DO NOT install yara-ctypes using pip install yara!!

PSutil for win64: https://github.com/giampaolo/psutil

WMI for win32: https://pypi.python.org/pypi/WMI/

Requests: pip install requests

Compiling rastrea2r
Make sure you have all the dependencies installed for the binary you are going to build on your Windows box. Then install:

Pywin32: http://sourceforge.net/projects/pywin32/files/ ** Windows only

Pyinstaller: https://github.com/pyinstaller/pyinstaller/wiki

Current functionality in v0.7
yara-disk: Yara scan for file/directory objects on disk

yara-mem: Yara scan for running processes in memory

memdump: Acquires a memory dump from the endpoint ** Windows only

triage: Collects triage information from the endpoint ** Windows only

** Notes

For memdump and triage modules, SMB shares must be set up in this specific way:

-- Binaries (sysinternals, batch files and others) must be located in a shared folder called TOOLS (read only)

\\path-to-share-folder\tools

-- Output is sent to a shared folder called DATA (write only)

\\path-to-share-folder\data

For yara-mem and yara-disk scans, the yara rules must be in the same directory where the server is executed from.

The RESTful API server stores data received in a file called results.txt in the same directory.

License
The content of this project itself is licensed under the Creative Commons Attribution 3.0 license, and the underlying source code used to format and display that content is licensed under the MIT license.

Credits & References
To my colleagues and friends Robert Gresham Jr. (@rwgresham) and Ryan O'Connor (@_remixed) for their contributions to the Triage module. Thanks folks!

To Ricardo Dias for the idea of using a REST server and his great paper on how to use Python and Yara with McAfee ePO: http://www.sans.org/reading-room/whitepapers/forensics/intelligence-driven-incident-response-yara-35542

Presentation on how to use rastrea2r and open source tools for Incident Response, Continuous Monitoring and Hunting (SANS @Night, McLean VA, February 2016): https://github.com/aboutsecurity/Talks-and-Presentations/blob/master/Ismael_Valenzuela-Hunting_for_IOCs_rastrea2r-Feb-2016.pdf

Presentation at BlackHat Arsenal 2016: https://github.com/aboutsecurity/Talks-and-Presentations/blob/master/Ismael_Valenzuela-Hunting_for_IOCs_rastrea2r-BH_Arsenal_2016.pdf

.. _change-log-label:

Change Log
==========

Version History
---------------

1.0 -   08-10-2018
==================

**Blackhat Arsanal Release**

- Moved the rastrea2r server to a new github project here_:
.. _here: https://github.com/rastrea2r/rastrea2r-server

- Modular implementation with python 3.4 and above supported now

- Introduced a new config (rastrea2r.ini) for rastrea2r client

- Support for the execution of Commands by specifying them using config files for triage module

- Support for executing the custom commands/batch scripts using the triage module

- Support for collecting the baseline information from the target devices

- Continuous integration support using travis.ci

- Automated documentation support using readthedocs.org


0.8 -   05-05-2018
==================

**Infrastructure Enhancements**

- Migrated the project from https://github.com/aboutsecurity/rastrea2r

- Introduced the new project folder structure

- Introduce travis ci pipeline : https://travis-ci.org/rastrea2r/rastrea2r

- Introduced make file for performing multiple targets such as coverage check, creating dists, creating docs etc

- Introduced placeholders for tests, examples

- Updated documentation, moved the documentation to http://rastrea2r.readthedocs.io/en/latest/dev/index.html


0.7.1 -   04-15-2016
====================

**Bug fixes**

- Fixed issue with the way Yara deals with archived files. Now yaradisk checks for the mime type of the file, and if it's an OpenXML Office document (docx, xlsx, pptx, etc.) it extracts the files in memory only before passing them to the Yara engine. Ref: https://github.com/BayshoreNetworks/yextend

- Fixed issue with SHA256 for memory dump file.


0.7 -   03-31-2016
==================

**Enhancements**

- Upgraded packages to latest versions: yara-python 3.4.0, bottle 0.12.9 and psutil 4.1.0.

- Windows binaries (client and server) packaged with pyinstaller 3.1.1 in one-file bundle executables.

- Hashes output files with SHA256 using buffers to reduce memory impact.

- Various code optimizations.


Bug tracker at https://github.com/aboutsecurity/rastrea2r/issues


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



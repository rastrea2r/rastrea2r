@echo off
title Rastrea2r Executables Generations

echo Generating the Exe for Win32 Platform
pyinstaller --noconfirm --log-level=WARN ^
    --onefile --nowindow ^
    --additional-hooks-dir="C:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\Common7\IDE" ^
    rastrea2r_win32.spec

echo Generating the Exe for Win32 Platform
pyinstaller --noconfirm --log-level=WARN ^
    --onefile --nowindow ^
    --additional-hooks-dir="C:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\Common7\IDE" ^
    rastrea2r_win64.spec

echo Windows Executables Generated Successfully
pause
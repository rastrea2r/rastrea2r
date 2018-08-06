@echo off
title Rastrea2r Executables Generations

echo Generating the Exe for Windows Platform
pyinstaller --noconfirm --log-level=WARN ^
    --onefile --nowindow ^
    rastrea2r_windows.spec

echo Windows Executables Generated Successfully
pause
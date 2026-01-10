@echo off
title Project Eyes On Installer
echo [*] Project Eyes On - Windows Installer
echo [*] Made by Y0oshi
echo.

echo [*] Installing Dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [!] Error installing dependencies. Make sure Python and Pip are installed!
    pause
    exit /b
)

echo.
echo [*] Creating 'eyeson' shortcut...
(
    echo @echo off
    echo python "%~dp0eyes.py" %%*
) > eyeson.bat

echo.
echo [+] Installation Complete!
echo [*] You can now type 'eyeson' to start the tool.
echo.
pause

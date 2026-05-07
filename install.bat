@echo off
title Project Eyes On Installer
echo [*] Project Eyes On - Windows Installer (v3.0)
echo [*] Made by Y0oshi
echo.

echo [*] Creating Virtual Environment...
python -m venv venv
if %errorlevel% neq 0 (
    echo [!] Error creating virtual environment. Ensure Python is installed and in PATH.
    pause
    exit /b
)

echo [*] Installing Dependencies into venv...
call venv\Scripts\activate.bat
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [!] Error installing dependencies.
    pause
    exit /b
)

echo.
echo [*] Creating 'eyeson' shortcut...
(
    echo @echo off
    echo "%~dp0venv\Scripts\python.exe" "%~dp0eyes.py" %%*
) > eyeson.bat

echo.
echo [+] Installation Complete!
echo [*] Virtual environment created in .\venv
echo [*] You can now type 'eyeson' to start the tool.
echo.
pause

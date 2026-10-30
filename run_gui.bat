@echo off
rem ==========================================================================
rem  tenable_net one-click launcher (Windows)
rem    - finds a suitable 64-bit Python 3.10-3.14 (offers to install 3.12)
rem    - creates .venv next to this file if it is missing or broken
rem    - installs requirements.txt when it changed or imports are broken
rem    - starts the desktop app
rem
rem  run_gui.bat          normal start (console closes, app opens)
rem  run_gui.bat debug    run the app in this console so errors are visible
rem
rem  Logs: logs\setup.log (pip), logs\gui-error.log (app crashes)
rem  Logic uses labels instead of nested ( ) blocks and relative paths only,
rem  so folders with spaces or parentheses in their names work.
rem ==========================================================================
setlocal
cd /d "%~dp0"
title tenable_net launcher

set "VENV=.venv"
set "VPY=.venv\Scripts\python.exe"
set "VPYW=.venv\Scripts\pythonw.exe"
set "STAMP=.venv\.requirements.sha256"
set "LOG=logs\setup.log"
set "PROBE=import sys,struct;v=sys.version_info[:2];sys.exit(0 if (3,10)<=v<=(3,14) and struct.calcsize('P')==8 else 1)"
set "TRIED_WINGET="
if not exist logs mkdir logs

rem --- 1. Reuse .venv if its Python still works ------------------------------
if not exist "%VPY%" goto :findpython
"%VPY%" -c "%PROBE%" >nul 2>&1
if not errorlevel 1 goto :requirements
echo The existing .venv is broken or uses an unsupported Python. Recreating it...
rmdir /s /q "%VENV%"

rem --- 2. Find a suitable Python ----------------------------------------------
:findpython
set "PY="
for %%V in (3.12 3.13 3.11 3.14 3.10) do call :trypy %%V
if defined PY goto :makevenv
python -c "%PROBE%" >nul 2>&1
if not errorlevel 1 set "PY=python"
if defined PY goto :makevenv

echo.
echo  No suitable Python found. tenable_net needs 64-bit Python 3.10 to 3.14.
echo  Pythons this computer has, if any:
py -0p 2>nul
python -c "import sys,struct;print('   python on PATH:',sys.version.split()[0],str(struct.calcsize('P')*8)+'-bit')" 2>nul
echo.
if defined TRIED_WINGET goto :nopython
where winget >nul 2>&1
if errorlevel 1 goto :nopython
choice /c YN /m " Install Python 3.12 (64-bit, just for your user) with winget now"
if errorlevel 2 goto :nopython
set "TRIED_WINGET=1"
winget install -e --id Python.Python.3.12 --scope user --accept-package-agreements --accept-source-agreements
if errorlevel 1 goto :nopython
rem This window doesn't see the new PATH yet, so add the usual per-user locations.
set "PATH=%LOCALAPPDATA%\Programs\Python\Launcher;%LOCALAPPDATA%\Programs\Python\Python312;%PATH%"
goto :findpython

:trypy
if defined PY goto :eof
py -%1 -c "%PROBE%" >nul 2>&1
if not errorlevel 1 set "PY=py -%1"
goto :eof

:nopython
echo  Install 64-bit Python 3.12 from https://www.python.org/downloads/windows/
echo  and tick "Add python.exe to PATH", then run this file again.
goto :fail

rem --- 3. Create the virtual environment --------------------------------------
:makevenv
echo Creating virtual environment with: %PY%
%PY% -m venv "%VENV%" >>"%LOG%" 2>&1
if errorlevel 1 goto :venvfail
if not exist "%VPY%" goto :venvfail

rem --- 4. Install requirements when requirements.txt changed or imports fail ---
:requirements
set "WANT="
for /f "delims=" %%H in ('certutil -hashfile requirements.txt SHA256 2^>nul ^| findstr /v ":"') do if not defined WANT set "WANT=%%H"
if defined WANT set "WANT=%WANT: =%"
set "HAVE="
if exist "%STAMP%" set /p HAVE=<"%STAMP%"
if not "%WANT%"=="%HAVE%" goto :install
"%VPY%" -c "import tenable_net.gui.app" >nul 2>&1
if errorlevel 1 goto :install
goto :launch

:install
echo.
echo Installing requirements into .venv (the first run takes a few minutes)...
echo.
"%VPY%" -m pip install --upgrade pip --log "%LOG%"
"%VPY%" -m pip install --prefer-binary -r requirements.txt --log "%LOG%"
if errorlevel 1 goto :pipfail
"%VPY%" -c "import tenable_net.gui.app" >>"%LOG%" 2>&1
if errorlevel 1 goto :importfail
if defined WANT >"%STAMP%" echo %WANT%
echo.
echo Requirements are installed.

rem --- 5. Launch -----------------------------------------------------------------
:launch
if /i "%~1"=="debug" goto :debug
if not exist "%VPYW%" goto :debug
echo Starting tenable_net...
start "" "%VPYW%" -m tenable_net gui
exit /b 0

:debug
echo Starting tenable_net in this console (close the app to return here)...
"%VPY%" -m tenable_net gui
if errorlevel 1 goto :fail
exit /b 0

rem --- Errors ------------------------------------------------------------------------
:venvfail
echo.
echo  Could not create the virtual environment with: %PY%
echo  Details are in %LOG%
goto :fail

:importfail
echo.
echo  Packages installed, but the app still can't be imported. The error is at
echo  the end of %LOG%. Deleting the .venv folder and running this file again
echo  often fixes a half-finished install.
goto :fail

:pipfail
echo.
echo  Installing requirements failed (see the messages above and %LOG%).
echo  Common fixes:
echo    - Behind a web proxy: run   set HTTPS_PROXY=http://your-proxy:port
echo      in a Command Prompt, then run run_gui.bat from that same window.
echo    - SSL inspection "certificate verify failed": point pip at your CA with
echo      .venv\Scripts\python -m pip config --site set global.cert C:\path\to\ca.pem
echo    - Then run this file again. Delete the .venv folder to start completely fresh.
goto :fail

:fail
echo.
pause
exit /b 1

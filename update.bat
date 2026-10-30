@echo off
rem ==========================================================================
rem  tenable_net updater (Windows)
rem    - checks GitHub for a newer version of this folder's branch (main)
rem    - shows what changed and updates with a fast-forward pull
rem    - ZIP download (no .git folder): offers to link the folder to GitHub
rem    - never touches .env, cache\, output\, logs\ or .venv\ (all git-ignored)
rem
rem  update.bat            check main and update if needed
rem  update.bat <branch>   use another branch
rem
rem  cmd.exe reads a running batch file from disk as it goes, so updating
rem  this file mid-run would break it. It re-runs itself from %TEMP% first.
rem  Logic uses labels instead of ( ) blocks so folder names with spaces or
rem  parentheses work.
rem ==========================================================================
if /i "%~1"=="--from-temp" goto :main
copy /y "%~f0" "%TEMP%\tenable_net_update.bat" >nul
if errorlevel 1 goto :selfcopyfail
"%TEMP%\tenable_net_update.bat" --from-temp "%~dp0." %1

:selfcopyfail
echo Could not copy the updater to %TEMP%.
pause
exit /b 1

:main
setlocal
cd /d "%~2"
if errorlevel 1 goto :fail
title tenable_net updater
set "REPO_URL=https://github.com/vayler/UFH_NetEng_Tenable.git"
set "BRANCH=main"
if not "%~3"=="" set "BRANCH=%~3"
echo tenable_net updater - folder: %CD%
echo.

rem --- 1. Git available? ---------------------------------------------------------
where git >nul 2>&1
if not errorlevel 1 goto :havegit
echo Git is not installed. The updater uses Git to download new versions.
where winget >nul 2>&1
if errorlevel 1 goto :nogit
choice /c YN /m " Install Git for Windows now with winget"
if errorlevel 2 goto :nogit
winget install -e --id Git.Git --accept-package-agreements --accept-source-agreements
if errorlevel 1 goto :nogit
rem This window doesn't see the new PATH yet, so add the usual install locations.
set "PATH=%ProgramFiles%\Git\cmd;%LOCALAPPDATA%\Programs\Git\cmd;%PATH%"
where git >nul 2>&1
if errorlevel 1 goto :nogit

:havegit
if exist ".git" goto :checkbranch

rem --- 2. ZIP download: link this folder to GitHub once ---------------------------
echo This folder isn't a git checkout yet (it was probably downloaded as a ZIP).
echo Linking it to GitHub replaces the program files with the latest %BRANCH% version.
echo Your .env, cache, reports, logs and .venv are kept.
echo.
choice /c YN /m " Link this folder to %REPO_URL% and update"
if errorlevel 2 goto :cancelled
git init -q
if errorlevel 1 goto :fail
git remote add origin "%REPO_URL%" 2>nul
git remote set-url origin "%REPO_URL%"
echo Downloading %BRANCH% ...
git fetch origin %BRANCH%
if errorlevel 1 goto :fetchfail
git checkout -q -f -B %BRANCH% origin/%BRANCH%
if errorlevel 1 goto :fail
git branch -q --set-upstream-to=origin/%BRANCH% %BRANCH%
goto :updated

rem --- 3. Make sure we're on the branch being updated ------------------------------
:checkbranch
set "CURBR="
for /f "delims=" %%B in ('git rev-parse --abbrev-ref HEAD 2^>nul') do set "CURBR=%%B"
if /i "%CURBR%"=="%BRANCH%" goto :fetch
echo This folder is on branch "%CURBR%", not "%BRANCH%".
choice /c YN /m " Switch to %BRANCH%"
if errorlevel 2 goto :cancelled
git fetch -q origin %BRANCH%
if errorlevel 1 goto :fetchfail
git checkout -q %BRANCH% 2>nul
if not errorlevel 1 goto :fetch
git checkout -q -b %BRANCH% --track origin/%BRANCH%
if errorlevel 1 goto :fail

rem --- 4. Compare with GitHub ------------------------------------------------------
:fetch
echo Checking GitHub for updates to %BRANCH% ...
git fetch -q origin %BRANCH%
if errorlevel 1 goto :fetchfail
set "BEHIND=0"
set "AHEAD=0"
set "LOCAL="
for /f %%N in ('git rev-list --count HEAD..origin/%BRANCH%') do set "BEHIND=%%N"
for /f %%N in ('git rev-list --count origin/%BRANCH%..HEAD') do set "AHEAD=%%N"
for /f %%H in ('git rev-parse --short HEAD') do set "LOCAL=%%H"
call :localversion
call :remoteversion
if "%BEHIND%"=="0" goto :uptodate
if not "%AHEAD%"=="0" goto :diverged

echo.
echo  Update available: version %LV% (%LOCAL%) -^> %RV%, %BEHIND% new change(s):
git --no-pager log --oneline --no-decorate -n 15 HEAD..origin/%BRANCH%
echo.
git diff --quiet HEAD
if errorlevel 1 goto :localchanges
choice /c YN /m " Install the update now"
if errorlevel 2 goto :cancelled
git merge --ff-only -q origin/%BRANCH%
if errorlevel 1 goto :fail
goto :updated

rem --- Program files edited locally ---------------------------------------------
:localchanges
echo  Some program files in this folder were changed locally:
git status --short --untracked-files=no
echo.
echo   K = keep your changes: set them aside, update, then re-apply them
echo   D = discard your changes and take the new version as-is
echo   C = cancel
choice /c KDC /m " Choose"
if errorlevel 3 goto :cancelled
if errorlevel 2 goto :discard
git stash push -q -m "update.bat: local changes before update"
if errorlevel 1 goto :fail
git merge --ff-only -q origin/%BRANCH%
if errorlevel 1 goto :fail
git stash pop -q
if not errorlevel 1 goto :updated
echo.
echo  Updated, but your local changes clash with the new version. They are still
echo  saved: run "git stash list" / "git stash pop" to recover them, or just keep
echo  the new version.
goto :updated

:discard
git reset -q --hard origin/%BRANCH%
if errorlevel 1 goto :fail
goto :updated

:diverged
echo.
echo  This copy has %AHEAD% local commit(s) that aren't on GitHub, and GitHub has
echo  %BEHIND% new one(s). Combine them from a Command Prompt in this folder with:
echo      git pull --rebase origin %BRANCH%
goto :fail

rem --- Results ----------------------------------------------------------------------
:uptodate
echo.
echo  You're up to date: version %LV% (%LOCAL%).
goto :launch

:updated
for /f %%H in ('git rev-parse --short HEAD') do set "LOCAL=%%H"
call :localversion
echo.
echo  Updated to version %LV% (%LOCAL%).
echo  New requirements, if any, are installed automatically the next time run_gui.bat starts.

:launch
echo.
if not exist "run_gui.bat" goto :done
choice /c YN /t 20 /d N /m " Start tenable_net now (defaults to No in 20 s)"
if errorlevel 2 goto :done
call run_gui.bat
exit /b 0

:done
pause
exit /b 0

rem --- Helpers ----------------------------------------------------------------------
:localversion
set "LV=?"
for /f tokens^=2^ delims^=^" %%V in ('findstr /b "__version__" tenable_net\__init__.py 2^>nul') do set "LV=%%V"
goto :eof

:remoteversion
set "RV=?"
for /f tokens^=2^ delims^=^" %%V in ('git show origin/%BRANCH%:tenable_net/__init__.py 2^>nul ^| findstr /b "__version__"') do set "RV=%%V"
goto :eof

rem --- Errors -----------------------------------------------------------------------
:nogit
echo.
echo  Install Git for Windows from https://git-scm.com/download/win and run this
echo  file again. Or download the latest ZIP from
echo  https://github.com/vayler/UFH_NetEng_Tenable  - Code - Download ZIP
echo  and copy your .env and cache folder into it.
goto :fail

:fetchfail
echo.
echo  Couldn't reach GitHub. Check that:
echo    - you're online. Behind a web proxy, run once:
echo        git config --global http.proxy http://your-proxy:port
echo    - you can sign in to GitHub with access to vayler/UFH_NetEng_Tenable.
echo      Git for Windows opens a browser sign-in the first time.
goto :fail

:cancelled
echo.
echo  Nothing was changed.
goto :done

:fail
echo.
echo  The update did not finish. Nothing in .env, cache or .venv was touched.
pause
exit /b 1

@echo off
setlocal EnableExtensions DisableDelayedExpansion
chcp 65001 >nul 2>&1
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
rem Discovery must not trigger Store or install-manager provisioning itself.
set "PYTHON_MANAGER_AUTOMATIC_INSTALL=false"
set "PYLAUNCHER_ALLOW_INSTALL="
set "PYLAUNCHER_ALWAYS_INSTALL="
set "PYLAUNCHER_DRYRUN="
set "SIA_ROOT=%~dp0"
set "SIA_NO_LAUNCH="
set "SIA_NO_BOOTSTRAP="
set "SIA_PS_OPTIONS=-NoLaunch"
set "SIA_BACKEND_ATTEMPTED="
set "SIA_READY="
set "SIA_WINGET_ATTEMPTED="
set "SIA_EXIT=1"

:arguments
if "%~1"=="" goto begin
if /i "%~1"=="--no-launch" goto no_launch
if /i "%~1"=="--no-bootstrap" goto no_bootstrap
echo Unknown installer option.
echo Usage: install.cmd [--no-launch] [--no-bootstrap]
exit /b 2
:no_launch
set "SIA_NO_LAUNCH=1"
shift
goto arguments
:no_bootstrap
set "SIA_NO_BOOTSTRAP=1"
set "SIA_PS_OPTIONS=-NoLaunch -NoBootstrap"
shift
goto arguments

:begin
echo SIA setup - checking this computer and preparing the app.
if not exist "%SIA_ROOT%scripts\windows_install.py" goto missing_source
if defined SIA_INSTALL_SKIP_POWERSHELL goto discover
if not exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" goto modern_powershell
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SIA_ROOT%install.ps1" %SIA_PS_OPTIONS%
set "SIA_EXIT=%ERRORLEVEL%"
if "%SIA_EXIT%"=="0" goto ready
if "%SIA_EXIT%"=="130" goto stopped
if "%SIA_EXIT%"=="10" goto failed
:modern_powershell
where.exe pwsh.exe >nul 2>&1
if errorlevel 1 goto discover
pwsh.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SIA_ROOT%install.ps1" %SIA_PS_OPTIONS%
set "SIA_EXIT=%ERRORLEVEL%"
if "%SIA_EXIT%"=="0" goto ready
if "%SIA_EXIT%"=="130" goto stopped
if "%SIA_EXIT%"=="10" goto failed

:discover
echo Trying the Python installer route automatically.
set "SIA_CANDIDATE_ARGS="
set "SIA_CANDIDATE="
if exist "%SIA_ROOT%.sia-python.path" set /p "SIA_CANDIDATE=" < "%SIA_ROOT%.sia-python.path"
call :try_python
set "SIA_CANDIDATE=%SIA_ROOT%.venv\Scripts\python.exe"
call :try_python
set "SIA_CANDIDATE=py.exe"
set "SIA_CANDIDATE_ARGS=-3"
call :try_python
set "SIA_CANDIDATE_ARGS="
for /f "delims=" %%P in ('where.exe python.exe 2^>nul') do (
    set "SIA_CANDIDATE=%%P"
    call :try_python
)
for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
    set "SIA_CANDIDATE=%%~fD\python.exe"
    call :try_python
)
for /f "tokens=2,*" %%A in ('reg.exe query HKCU\Software\Python\PythonCore /s /v ExecutablePath 2^>nul ^| findstr.exe REG_SZ') do (
    set "SIA_CANDIDATE=%%B"
    call :try_python
)
for /f "tokens=2,*" %%A in ('reg.exe query HKLM\Software\Python\PythonCore /s /v ExecutablePath 2^>nul ^| findstr.exe REG_SZ') do (
    set "SIA_CANDIDATE=%%B"
    call :try_python
)
for /f "tokens=2,*" %%A in ('reg.exe query HKCU\Software\Python\PythonCore /s /ve 2^>nul ^| findstr.exe REG_SZ') do (
    set "SIA_CANDIDATE=%%B\python.exe"
    call :try_python
)
for /f "tokens=2,*" %%A in ('reg.exe query HKLM\Software\Python\PythonCore /s /ve 2^>nul ^| findstr.exe REG_SZ') do (
    set "SIA_CANDIDATE=%%B\python.exe"
    call :try_python
)
if defined SIA_READY goto ready
if "%SIA_EXIT%"=="130" goto stopped
if defined SIA_BACKEND_ATTEMPTED goto failed
if defined SIA_NO_BOOTSTRAP goto no_python
if defined SIA_WINGET_ATTEMPTED goto no_python
where.exe winget.exe >nul 2>&1
if errorlevel 1 goto no_python
set "SIA_WINGET_ATTEMPTED=1"
echo Python is missing. Installing the official per-user Python package.
winget.exe install --id Python.Python.3.14 --exact --source winget --scope user --silent --accept-package-agreements --accept-source-agreements --disable-interactivity
goto discover

:try_python
if defined SIA_BACKEND_ATTEMPTED exit /b 0
if not defined SIA_CANDIDATE exit /b 0
rem Ignore Store aliases: probing them can open the Store instead of Python.
if /i not "%SIA_CANDIDATE:\Microsoft\WindowsApps\=%"=="%SIA_CANDIDATE%" exit /b 0
"%SIA_CANDIDATE%" %SIA_CANDIDATE_ARGS% -c "import sys, venv, ensurepip; sys.exit(0 if sys.version_info >= (3,11) else 1)" >nul 2>&1
if errorlevel 1 exit /b 0
set "SIA_BACKEND_ATTEMPTED=1"
"%SIA_CANDIDATE%" %SIA_CANDIDATE_ARGS% "%SIA_ROOT%scripts\windows_install.py" --no-launch
set "SIA_EXIT=%ERRORLEVEL%"
if "%SIA_EXIT%"=="0" set "SIA_READY=1"
exit /b 0

:ready
if not exist "%SIA_ROOT%.sia-python.path" goto missing_marker
echo.
echo SIA is ready. Next time, open Start-SIA.cmd in this folder.
if defined SIA_NO_LAUNCH exit /b 0
pushd "%SIA_ROOT%"
if errorlevel 1 goto failed
"%ComSpec%" /d /c Start-SIA.cmd
set "SIA_EXIT=%ERRORLEVEL%"
popd
exit /b %SIA_EXIT%

:missing_source
echo Extract the complete download first, then open install.cmd in the extracted folder.
goto failed
:missing_marker
echo Setup did not produce a verified app launcher. Installation is not complete.
goto failed
:no_python
echo No usable Python was found and automatic provisioning could not complete.
echo Your organization's software policy or download access may require IT assistance.
echo Install an approved Python 3.11 or newer, then rerun this same installer.
set "SIA_EXIT=2"
goto failed
:stopped
echo Setup interrupted. Your configuration, credentials, inputs, and reports are preserved.
echo Reopen install.cmd to verify the selected runtime and finish setup.
exit /b 130
:failed
if "%SIA_EXIT%"=="0" set "SIA_EXIT=1"
echo.
echo Setup could not finish. Review the error above, then rerun this same installer.
if not defined SIA_NO_LAUNCH pause
exit /b %SIA_EXIT%

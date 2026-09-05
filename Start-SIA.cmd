@echo off
setlocal EnableExtensions DisableDelayedExpansion
chcp 65001 >nul 2>&1
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
set "SIA_ROOT=%~dp0"
set "SIA_REPAIRED="
pushd "%SIA_ROOT%"
if errorlevel 1 exit /b 1

:locate
set "SIA_PYTHON="
if exist "%SIA_ROOT%.sia-python.path" set /p "SIA_PYTHON=" < "%SIA_ROOT%.sia-python.path"
if not defined SIA_PYTHON goto repair
if not exist "%SIA_PYTHON%" goto repair
"%SIA_PYTHON%" "%SIA_ROOT%scripts\windows_install.py" --check >nul 2>&1
set "SIA_EXIT=%ERRORLEVEL%"
if "%SIA_EXIT%"=="130" goto stopped
if not "%SIA_EXIT%"=="0" goto repair
"%SIA_PYTHON%" -m sia.bootstrap %*
set "SIA_EXIT=%ERRORLEVEL%"
popd
if not "%SIA_EXIT%"=="0" if not "%SIA_EXIT%"=="130" if "%~1"=="" pause
exit /b %SIA_EXIT%

:repair
if defined SIA_REPAIRED goto failed
set "SIA_REPAIRED=1"
echo Preparing or repairing the SIA app automatically.
"%ComSpec%" /d /c install.cmd --no-launch
set "SIA_EXIT=%ERRORLEVEL%"
if "%SIA_EXIT%"=="130" goto stopped
if not "%SIA_EXIT%"=="0" goto failed
goto locate

:stopped
echo SIA startup cancelled.
popd
exit /b 130

:failed
echo SIA could not start. Run install.cmd to see the setup details and retry.
popd
if "%~1"=="" pause
exit /b 1

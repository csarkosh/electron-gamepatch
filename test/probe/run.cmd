@echo off
rem run.cmd <dir containing electron.exe> [rounds] — exit 0 iff every round relocked first try and saw Esc while locked.
setlocal
if "%~1"=="" ( echo run.cmd: usage: run.cmd ^<dir with electron.exe^> [rounds] 1>&2 & exit /b 2 )
set "APP=%~f1"
if not exist "%APP%\electron.exe" ( echo run.cmd: no electron.exe in %APP% 1>&2 & exit /b 2 )
set "ROUNDS=%~2"
if "%ROUNDS%"=="" set "ROUNDS=3"
cd /d "%~dp0"
"%APP%\electron.exe" .
exit /b %ERRORLEVEL%

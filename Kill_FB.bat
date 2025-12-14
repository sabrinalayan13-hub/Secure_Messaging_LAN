@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

echo =========================================
echo Kill_FB.bat (PID-first, port-fallback)
echo Root: %cd%
echo =========================================
echo.

REM -------------------------
REM 1) Try PID files (preferred)
REM -------------------------
set "KILLED=0"

if exist ".\.run\backend.pid" (
  for /f "usebackq delims=" %%P in (".\.run\backend.pid") do set "BPID=%%P"
  set "BPID=!BPID: =!"
  if not "!BPID!"=="" (
    echo Killing backend PID !BPID! ...
    taskkill /PID !BPID! /F /T >nul 2>&1
    set "KILLED=1"
    del ".\.run\backend.pid" >nul 2>&1
  )
)

if exist ".\.run\frontend.pid" (
  for /f "usebackq delims=" %%P in (".\.run\frontend.pid") do set "FPID=%%P"
  set "FPID=!FPID: =!"
  if not "!FPID!"=="" (
    echo Killing frontend PID !FPID! ...
    taskkill /PID !FPID! /F /T >nul 2>&1
    set "KILLED=1"
    del ".\.run\frontend.pid" >nul 2>&1
  )
)

REM -------------------------
REM 2) Fallback: kill by port if PID files missing
REM -------------------------
if "%KILLED%"=="0" (
  echo PID files not found. Falling back to killing by port...

  for /f "tokens=5" %%P in ('netstat -ano ^| findstr :8000 ^| findstr LISTENING') do (
    echo Killing backend listener PID %%P (port 8000)...
    taskkill /PID %%P /F /T >nul 2>&1
  )

  for /f "tokens=5" %%P in ('netstat -ano ^| findstr :5173 ^| findstr LISTENING') do (
    echo Killing frontend listener PID %%P (port 5173)...
    taskkill /PID %%P /F /T >nul 2>&1
  )
)

echo.
echo Verification:
netstat -ano | findstr :8000
netstat -ano | findstr :5173
echo.

pause
endlocal

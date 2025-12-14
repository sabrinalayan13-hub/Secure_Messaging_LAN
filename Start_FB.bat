@echo off
setlocal EnableExtensions

REM ==================================================
REM Anchor to project root
REM ==================================================
cd /d "%~dp0"

REM ==================================================
REM Detect folders
REM ==================================================
if exist ".\backend\main.py" (
  set "BACKEND_DIR=backend"
) else if exist ".\Backend\main.py" (
  set "BACKEND_DIR=Backend"
) else (
  echo [ERROR] backend main.py not found under: %cd%
  pause & exit /b 1
)

if exist ".\frontend\package.json" (
  set "FRONTEND_DIR=frontend"
) else if exist ".\Frontend\package.json" (
  set "FRONTEND_DIR=Frontend"
) else (
  echo [ERROR] frontend package.json not found under: %cd%
  pause & exit /b 1
)

REM ==================================================
REM Ensure .run directory exists
REM ==================================================
if not exist ".\.run" mkdir ".\.run" >nul 2>&1

REM ==================================================
REM Ensure backend venv python exists
REM ==================================================
if not exist ".\%BACKEND_DIR%\venv\Scripts\python.exe" (
  echo [ERROR] venv not found:
  echo   .\%BACKEND_DIR%\venv\Scripts\python.exe
  pause & exit /b 1
)

REM ==================================================
REM OPTION B: Create/Reuse a stable JWT secret
REM Stored at: .\.run\jwt_secret.txt
REM ==================================================
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$p = '.\.run\jwt_secret.txt'; " ^
  "if (!(Test-Path $p)) { " ^
  "  $s = [Convert]::ToBase64String((1..32 | ForEach-Object {Get-Random -Maximum 256})); " ^
  "  Set-Content -NoNewline -Path $p -Value $s; " ^
  "} "

for /f "usebackq delims=" %%S in (".\.run\jwt_secret.txt") do set "JWT_SECRET=%%S"

echo Using stable JWT secret (prefix): %JWT_SECRET:~0,6%******

REM ==================================================
REM Start backend (JWT_SECRET inherited by child process)
REM ==================================================
echo Starting backend...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$env:JWT_SECRET = '%JWT_SECRET%'; " ^
  "$wd = (Resolve-Path '.\%BACKEND_DIR%').Path; " ^
  "$py = (Resolve-Path '.\%BACKEND_DIR%\venv\Scripts\python.exe').Path; " ^
  "$p = Start-Process -PassThru -WorkingDirectory $wd -FilePath $py -ArgumentList @('-m','uvicorn','main:app','--reload','--host','0.0.0.0','--port','8000'); " ^
  "Set-Content -NoNewline -Path '.\.run\backend.pid' -Value $p.Id"

timeout /t 2 /nobreak >nul

REM ==================================================
REM Start frontend
REM ==================================================
echo Starting frontend...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$wd = (Resolve-Path '.\%FRONTEND_DIR%').Path; " ^
  "$npm = (Get-Command npm.cmd -ErrorAction Stop).Source; " ^
  "$p = Start-Process -PassThru -WorkingDirectory $wd -FilePath $npm -ArgumentList @('run','dev'); " ^
  "Set-Content -NoNewline -Path '.\.run\frontend.pid' -Value $p.Id"

echo.
echo =========================================
echo Backend Docs: http://127.0.0.1:8000/docs
echo Frontend:    http://localhost:5173
echo JWT secret stored at: .\.run\jwt_secret.txt
echo =========================================
echo.

endlocal

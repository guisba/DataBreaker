@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title DataBreaker

echo [DataBreaker] Checking Python...
set "PYTHON_CMD="
where py >nul 2>nul
if %errorlevel%==0 set "PYTHON_CMD=py -3"
if not defined PYTHON_CMD (
  where python >nul 2>nul
  if %errorlevel%==0 set "PYTHON_CMD=python"
)
if not defined PYTHON_CMD (
  echo.
  echo Python 3.11 or newer was not found.
  echo Install Python from https://www.python.org/downloads/ and run this file again.
  pause
  exit /b 1
)

%PYTHON_CMD% -c "import sys; assert sys.version_info >= (3,11), 'Python 3.11+ is required'" >nul 2>nul
if errorlevel 1 (
  echo Python 3.11 or newer is required.
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo [DataBreaker] Creating isolated environment...
  %PYTHON_CMD% -m venv .venv
  if errorlevel 1 goto :fail
)

set "VENV_PY=.venv\Scripts\python.exe"
echo [DataBreaker] Installing required dependencies...
"%VENV_PY%" -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 goto :fail

"%VENV_PY%" -c "import fastapi,uvicorn,multipart,pypdf,mutagen; import databreaker; print('DataBreaker', databreaker.__version__, 'ready')"
if errorlevel 1 goto :fail

echo [DataBreaker] Starting locally at http://127.0.0.1:8732
"%VENV_PY%" -m databreaker
exit /b %errorlevel%

:fail
echo.
echo DataBreaker setup failed. Review the error above.
pause
exit /b 1

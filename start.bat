@echo off
cd /d "%~dp0"
where py >nul 2>nul
if not errorlevel 1 (
  py -3 -m bft app %*
  goto done
)
where python >nul 2>nul
if not errorlevel 1 (
  python -m bft app %*
  goto done
)
echo Python 3.9 or newer is needed: https://www.python.org/downloads/
pause
:done

@echo off
REM ===================================================================
REM  Build ipID.exe  -- a single double-clickable file, no Python or
REM  pip needed on the machine that RUNS it. You only need Python +
REM  internet on the machine that BUILDS it (run this once).
REM
REM  Usage:  double-click this file, or run  build_windows.bat
REM  Result: dist\ipID.exe
REM ===================================================================

echo [*] Installing build dependencies...
python -m pip install --upgrade pyinstaller flask openpyxl
if errorlevel 1 (
  echo.
  echo [!] Python was not found. Install Python 3 from python.org
  echo     ^(check "Add Python to PATH" during install^), then re-run this.
  pause
  exit /b 1
)

echo.
echo [*] Building ipID.exe ...
pyinstaller --onefile --name ipID ^
  --add-data "templates;templates" ^
  --hidden-import importers ^
  --hidden-import ipident ^
  --hidden-import store ^
  --hidden-import openpyxl ^
  app.py

echo.
echo ============================================================
echo  Done.  Your app is here:   dist\ipID.exe
echo  Double-click it -- it starts the server and opens your
echo  browser to the dashboard automatically.
echo  A file "ipid.db" is created next to the exe to hold history.
echo ============================================================
pause

#!/usr/bin/env bash
# ===================================================================
#  Build a single-file ipID binary for macOS / Linux (no Python
#  needed on the machine that RUNS it). Run this once on the same
#  OS you want the binary for -- a Mac build runs on Macs, a Linux
#  build runs on Linux (you can't cross-build a Windows .exe here;
#  use build_windows.bat on Windows for that).
#
#  Usage:  ./build_unix.sh
#  Result: dist/ipID
# ===================================================================
set -e

echo "[*] Installing build dependencies..."
python3 -m pip install --upgrade pyinstaller flask openpyxl

echo "[*] Building ipID ..."
pyinstaller --onefile --name ipID \
  --add-data "templates:templates" \
  --hidden-import importers \
  --hidden-import ipident \
  --hidden-import store \
  --hidden-import openpyxl \
  app.py

echo ""
echo "============================================================"
echo " Done.  Your app is here:   dist/ipID"
echo " Run it:  ./dist/ipID   (starts the server + opens browser)"
echo " A file 'ipid.db' is created next to it to hold history."
echo "============================================================"

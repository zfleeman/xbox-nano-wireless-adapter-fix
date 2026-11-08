@echo off
rem Starts the xdongle user-mode driver. Extra arguments are passed through (e.g. --debug).
cd /d "%~dp0"
".venv\Scripts\python.exe" -m xdongle %*

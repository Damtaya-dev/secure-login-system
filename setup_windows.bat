@echo off
cd /d "%~dp0"
py -3 -m venv .venv
if errorlevel 1 (echo Python 3 not found & pause & exit /b 1)
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 (echo Dependency installation failed & pause & exit /b 1)
.venv\Scripts\python.exe setup.py
pause

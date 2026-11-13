@echo off
rem Start the VulnForge dashboard on Windows (installs first if needed). Wraps start.ps1.
rem   start.cmd                -> http://127.0.0.1:8787
rem   start.cmd --port 8788
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1" %*
if errorlevel 1 (
  rem Keep the window open on failure so a double-click still shows the error.
  if not defined CI pause
  exit /b 1
)

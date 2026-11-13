@echo off
rem VulnForge installer for Windows. Wraps install.ps1 so no execution-policy change is needed.
rem   install.cmd              install or update
rem   install.cmd -Recreate    delete .venv and start over
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
if errorlevel 1 (
  rem Keep the window open on failure so a double-click still shows the error.
  if not defined CI pause
  exit /b 1
)

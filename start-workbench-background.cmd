@echo off
rem Runs the background launcher with a one-shot execution-policy bypass so the
rem scheduled task does not depend on the machine policy.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-workbench-background.ps1" %*

@echo off
rem Foreground launcher; Ctrl+C stops the workbench. For a persistent service use
rem start-workbench-background.cmd instead.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-workbench.ps1" %*

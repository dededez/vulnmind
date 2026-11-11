param([int]$Port=8765)
$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot
$taskPython=Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $taskPython)) { throw 'Project Python environment not found. See docs/WORKBENCH.md.' }
Write-Host "Opening VulnMind at http://127.0.0.1:$Port (Ctrl+C to stop)"
& $taskPython -m vulnmind ui --port $Port

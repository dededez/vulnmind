param([int]$Port=8765,[switch]$Stop)
$ErrorActionPreference='Stop'
$taskName='VulnMind-Workbench-Local'
$taskScript=Join-Path $PSScriptRoot 'start-workbench.ps1'
$taskActionArgs='-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "'+$taskScript+'" -Port '+$Port
$existing=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) {
    $boundPath=[string]$existing.Actions[0].Arguments
    if ($boundPath -notlike ('*'+$taskScript+'*')) {
        throw 'Existing task is not bound to this workspace; refusing to touch it.'
    }
}
if ($Stop) {
    if ($existing) { Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2
    $listener=Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
    if ($listener) { Stop-Process -Id $listener.OwningProcess -Force -ErrorAction SilentlyContinue }
    Write-Output 'Local workbench stopped.'
    return
}
# Re-register every time so execution-policy and port arguments stay authoritative.
if ($existing) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name
$principal=New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
$action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $taskActionArgs -WorkingDirectory $PSScriptRoot
# On-demand only: no login/startup/periodic trigger, no password, no elevation.
$settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -Hidden
Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Description 'On-demand local VulnMind workbench; no automatic scan.' | Out-Null
Start-ScheduledTask -TaskName $taskName
for ($i=0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 700
    $listener=Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
    if ($listener) { break }
}
if (-not $listener) {
    $info=Get-ScheduledTaskInfo -TaskName $taskName
    throw ('Workbench did not start (task result '+$info.LastTaskResult+'). See .devtools\workbench-ui-error.log.')
}
Write-Output ('Local workbench started: http://127.0.0.1:'+$Port)

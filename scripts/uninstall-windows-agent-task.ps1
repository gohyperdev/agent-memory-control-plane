<# Removes the current user's AMCP Agent Scheduled Task. #>
[CmdletBinding()]
param(
    [string]$TaskName = "AMCP Agent"
)

$ErrorActionPreference = "Stop"

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw "This uninstaller is only supported on Windows."
}

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -eq $task) {
    Write-Host "AMCP Agent task '$TaskName' is not installed."
    exit 0
}

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
Write-Host "Removed AMCP Agent task '$TaskName'."

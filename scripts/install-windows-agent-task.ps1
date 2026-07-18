<#
Installs AMCP Agent as a per-user Windows Scheduled Task. Run from an elevated
PowerShell only if local policy requires it; the task itself runs at limited
privileges for the current interactive user. No token is written to the task.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AgentBin,
    [string]$TaskName = "AMCP Agent",
    [string]$PipeName = "\\.\pipe\com.gohyperdev.amcp.agent"
)

$ErrorActionPreference = "Stop"

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw "This installer is only supported on Windows."
}
if (-not [System.IO.Path]::IsPathRooted($AgentBin)) {
    throw "AgentBin must be an absolute path."
}

$resolvedAgent = (Resolve-Path -LiteralPath $AgentBin).Path
if (-not (Test-Path -LiteralPath $resolvedAgent -PathType Leaf)) {
    throw "AMCP Agent binary was not found: $resolvedAgent"
}
if (-not $PipeName.StartsWith("\\.\pipe\")) {
    throw "PipeName must be a local Windows named pipe (\\.\pipe\...)."
}

$arguments = "--socket `"$PipeName`" serve"
$action = New-ScheduledTaskAction -Execute $resolvedAgent -Argument $arguments
$trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "AMCP local Agent (no credential is stored in this task)" -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-Host "Installed and started per-user AMCP Agent task '$TaskName'."
Write-Host "The task contains no token. Configure a platform credential store before enrolling remote hosts."

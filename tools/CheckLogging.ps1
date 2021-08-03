function Get-LogSettings {

$Includecmdline = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled

if ($Includecmdline) {
    Write-Host "Audit Process Creation is Enabled"
}
else {
    Write-Host "Audit Process Creation is Disabled"
}

$ModuleLogging = (Get-ItemProperty 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue).EnableModuleLogging

if ($ModuleLogging) {
    Write-Host "Powershell Module Logging is Enabled"
}
else {
    Write-Host "Powershell Module Logging is Disabled"
}

$ScriptBlockLogging = (Get-ItemProperty 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging

if ($ScriptBlockLogging) {
    Write-Host "Powershell ScriptBlock Logging is Enabled"
}
else {
    Write-Host "Powershell ScriptBlock Logging is Disabled"
}

$Transcript = (Get-ItemProperty 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue).EnableTranscripting

if ($Transcript) {
    Write-Host "Powershell Transcript Logging is Enabled"
}
else {
    Write-Host "Powershell Transcript Logging is Disabled"
}
}
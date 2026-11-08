# Enable or disable starting xdongle (hidden, no console) when you log in.
#   powershell -ExecutionPolicy Bypass -File autostart.ps1 -Enable
#   powershell -ExecutionPolicy Bypass -File autostart.ps1 -Disable
param([switch]$Enable, [switch]$Disable)

$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$lnk = Join-Path ([Environment]::GetFolderPath('Startup')) 'xdongle.lnk'

if ($Disable) {
    Remove-Item $lnk -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -Filter "Name='pythonw.exe'" |
        Where-Object { $_.CommandLine -match '-m xdongle' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
    Write-Host "Autostart removed and running xdongle stopped."
    return
}
if (-not $Enable) { Write-Host "Use -Enable or -Disable"; return }

$ws = New-Object -ComObject WScript.Shell
$s = $ws.CreateShortcut($lnk)
$s.TargetPath = Join-Path $dir '.venv\Scripts\pythonw.exe'
$s.Arguments = '-m xdongle'
$s.WorkingDirectory = $dir
$s.Description = 'xdongle - Xbox Wireless Adapter user-mode driver'
$s.Save()
Start-Process -FilePath $s.TargetPath -ArgumentList '-m xdongle' -WorkingDirectory $dir -WindowStyle Hidden
Write-Host "Autostart enabled ($lnk) and xdongle started in the background. Log: $dir\xdongle.log"

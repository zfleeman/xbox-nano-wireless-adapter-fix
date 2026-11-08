# Captures an ETW trace of the Xbox GIP driver (xboxgip.sys) while a controller connects.
# Run from an ELEVATED PowerShell:
#   powershell -ExecutionPolicy Bypass -File capture-gip-trace.ps1 -Tag <name>
param([int]$Seconds = 60, [string]$Tag = 'nano')

$ErrorActionPreference = 'Stop'
$d = Split-Path -Parent $MyInvocation.MyCommand.Path
$etl = Join-Path $d "gip-$Tag.etl"
$xml = Join-Path $d "gip-$Tag.xml"
$session = 'XboxGipTrace'

# TraceLogging provider GUIDs pulled from the provider metadata blobs inside the binaries
$providers = @(
  '{2f294903-5481-4aa0-b4ef-14784cc95ce6}',  # Microsoft.Windows.Xbox.GIP            (xboxgip.sys)
  '{d4b7c96a-4e72-a6a5-141e-afad4ac86c9d}'   # Microsoft.Xbox.Accessory.Radio.MediaTek (mt7612US.sys, dongle radio)
)

logman stop $session -ets 2>$null | Out-Null
Remove-Item $etl, $xml -ErrorAction SilentlyContinue

logman create trace $session -ets -o $etl -mode Sequential -bs 1024 -nb 64 256 | Out-Null
foreach ($p in $providers) { logman update trace $session -ets -p $p 0xffffffffffffffff 0xff | Out-Null }

Write-Host ""
Write-Host "Tracing for $Seconds seconds. NOW: turn the controller ON (or press its pair button)." -ForegroundColor Yellow
for ($i = $Seconds; $i -gt 0; $i--) { Write-Host -NoNewline "`r$i s remaining   "; Start-Sleep 1 }
Write-Host ""

logman stop $session -ets | Out-Null
tracerpt $etl -o $xml -of XML -y | Out-Null

# Also save the xboxgip allowlist and what PnP sees right now
reg export "HKLM\SYSTEM\CurrentControlSet\Services\xboxgip" (Join-Path $d "xboxgip-reg-$Tag.reg") /y | Out-Null
Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match 'VID_045E|GIP|XBOX' } |
  Select-Object Status, Class, FriendlyName, InstanceId | Out-File (Join-Path $d "pnp-$Tag.txt") -Width 300

Write-Host "Done. Wrote $etl and $xml" -ForegroundColor Green

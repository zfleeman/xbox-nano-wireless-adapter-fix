# Sets up xdongle in this folder: checks the prerequisites, builds a Python virtual environment with the
# hash-checked packages from requirements.txt, then turns on start-at-logon. Doesn't need admin and installs no drivers.
#   powershell -ExecutionPolicy Bypass -File install.ps1               (set up and start at logon)
#   powershell -ExecutionPolicy Bypass -File install.ps1 -NoAutostart  (set up only; run with run-xdongle.cmd)
param([switch]$NoAutostart)
$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $dir

# 1. Python 3.12 or newer, through the "py" launcher that the python.org installer adds.
if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "Python isn't installed. Install Python 3.12 or newer from https://www.python.org/downloads/windows/ and run this again."
}
$ver = & py -3 -c "import sys; print('%d.%d' % sys.version_info[:2])"
if ([version]$ver -lt [version]'3.12') { throw "Found Python $ver. xdongle needs Python 3.12 or newer." }
Write-Host "Python $ver found."

# 2. ViGEmBus creates the virtual Xbox 360 controllers. Install it yourself first, so you choose the version.
if (-not (Get-Service ViGEmBus -ErrorAction SilentlyContinue)) {
    throw "ViGEmBus isn't installed. Install ViGEmBus_1.22.0_x64_x86_arm64.exe from https://github.com/nefarius/ViGEmBus/releases/tag/v1.22.0 and run this again."
}
Write-Host "ViGEmBus found."

# 3. Virtual environment in .venv. vgamepad's setup.py launches its own bundled (older) ViGEmBus installer when it
#    doesn't recognize the installed one, so tell it not to. --require-hashes rejects any package file that differs.
if (-not (Test-Path .venv\Scripts\python.exe)) { & py -3 -m venv .venv }
$env:VGAMEPAD_SKIP_VIGEMBUS_INSTALL = 'true'
& .venv\Scripts\python.exe -m pip install --disable-pip-version-check --require-hashes -r requirements.txt
if ($LASTEXITCODE) { throw "pip install failed (exit code $LASTEXITCODE)." }

# 4. The adapter must use the WinUSB driver (the Zadig step in the README), or xdongle can't open it.
$adapter = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object InstanceId -like 'USB\VID_045E&PID_02FE\*'
if (-not $adapter) {
    Write-Warning "The Xbox Wireless Adapter (045E:02FE) isn't plugged in, so its driver couldn't be checked."
} else {
    $service = (Get-PnpDeviceProperty -InstanceId $adapter[0].InstanceId -KeyName DEVPKEY_Device_Service).Data
    if ($service -ne 'WinUSB') {
        Write-Warning "The adapter still uses the '$service' driver. Do the Zadig step in the README, then run xdongle."
    } else {
        Write-Host "The adapter uses WinUSB."
    }
}

if ($NoAutostart) {
    Write-Host "Set up. Start xdongle with run-xdongle.cmd."
} else {
    & (Join-Path $dir 'autostart.ps1') -Enable
}

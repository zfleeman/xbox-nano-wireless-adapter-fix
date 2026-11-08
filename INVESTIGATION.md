# Why the Xbox Nano doesn't work on the Xbox Wireless Adapter in Windows

This is the evidence behind xdongle, and how to check it on your own PC.

## What Windows does

Windows handles the adapter with two Microsoft drivers: `mt7612US.sys` runs the adapter's radio, and `xboxgip.sys` (with `devauthe.sys` for device authentication) speaks the Game Input Protocol (GIP) to each controller. `xboxgip.sys` logs what it does to an Event Tracing for Windows (ETW) provider named `Microsoft.Windows.Xbox.GIP` (`{2f294903-5481-4aa0-b4ef-14784cc95ce6}`). [`capture-gip-trace.ps1`](capture-gip-trace.ps1) records that provider while you turn a controller on.

With the Nano, the trace repeats this every 4.6 seconds for as long as the controller is on (PID 2892 is `0x0B4C`, the Nano's product ID):

```
15:46:00.391  DeviceConnected     PID=2892
15:46:01.128  DeviceSecurity      SecurityPass=0 SecurityIterations=5 AuthDuration=120 DevAuthVersion=0
15:46:01.159  DeviceDisconnected  PID=2892 Reason=3
15:46:05.000  DeviceConnected     PID=2892
15:46:05.751  DeviceSecurity      SecurityPass=0 SecurityIterations=5 AuthDuration=120 DevAuthVersion=0
15:46:05.783  DeviceDisconnected  PID=2892 Reason=3
...
```

The same adapter with an Xbox Series controller (PID 2834, `0x0B12`) passes on the first try and stays connected:

```
15:47:26.103  DeviceConnected     PID=2834
15:47:26.952  DeviceSecurity      SecurityPass=1 SecurityIterations=1 AuthDuration=736 DevAuthVersion=1
```

So the Nano reaches Windows fine over the radio. Windows tries to authenticate it five times, fails (`SecurityPass=0`), and disconnects it. No device is ever created in Device Manager, which is why games see nothing and the controller's light keeps blinking.

## Why Linux works

On Linux, the [`xone`](https://github.com/dlundqvist/xone) driver loads the same adapter firmware (byte for byte, SHA-256 `48084d9f…`) and runs the same authentication handshake. But it doesn't check the controller's certificate, and it doesn't disconnect a controller when the handshake fails. Input works either way.

xdongle shows what the Nano does differently. During the handshake, it answers with a protocol version that neither Windows' driver nor `xone` supports. Its reply starts `00 c2 00 02 00 04 02 03`, where the Series controller uses the known version 2 handshake. xdongle logs `authentication problem: short client hello (input continues)` and keeps the controller connected. The Nano also sends an unknown GIP command (`0x1F`, payload `02`) about once a second, which xdongle ignores.

## What was ruled out

These were all checked on Windows 11 26H2 with `xboxgip.sys` and `devauthe.sys` version 10.0.26100.9818:

- **Registry settings and feature flags.** Reading `xboxgip.sys` shows that the disconnect after a failed check is switched on unconditionally when the driver starts. No registry value or Windows feature flag turns it off.
- **The allowlist key.** `HKLM\SYSTEM\CurrentControlSet\Services\xboxgip\...\allowlist` is a record the driver writes after a device passes. The driver doesn't read it before the check, so it can't be used to skip it.
- **Developer Mode.** It only lets administrators open an extra admin interface to the driver. It doesn't skip authentication.
- **Microsoft's Xbox accessory driver pack** (aka.ms/DownloadXBOXAccessoryDrivers, often suggested online). Its three drivers only list the controllers' USB and Bluetooth IDs, not the Nano over the adapter (`0B4C`). The Nano tested here had firmware 6.19.50.0.
- **The optional "Xbox Wireless Adapter for Windows" driver in Windows Update.** It's a 2015 driver for the older adapter (`045E:02E6`). The adapter driver packages only contain `mt7612US.sys` and the firmware. The authentication check lives in `xboxgip.sys` and `devauthe.sys`, which only change through Windows cumulative updates.

## Check whether Windows has fixed it

A real fix from Microsoft will most likely arrive as a newer `xboxgip.sys` or `devauthe.sys` in a Windows update.

1. Check the version: `(Get-Item C:\Windows\System32\drivers\xboxgip.sys).VersionInfo.FileVersion`. If it's still 10.0.26100.9818, nothing has changed.
2. If it's newer, put the adapter back on Microsoft's driver (README, [Undo](README.md#undo) steps 1 and 2).
3. From an admin PowerShell, run `powershell -ExecutionPolicy Bypass -File capture-gip-trace.ps1 -Tag nano` and turn the Nano on within 60 seconds.
4. Open `gip-nano.xml` and search for `SecurityPass`. If it's `1` and no `DeviceDisconnected` follows, Windows supports the Nano now and you don't need xdongle. If it's still `0`, run Zadig again to go back to xdongle.

The script also saves `xboxgip-reg-nano.reg` (the driver's registry settings) and `pnp-nano.txt` (the Xbox devices Windows sees). The trace and those files include device IDs and the adapter's serial number, so check them before sharing.

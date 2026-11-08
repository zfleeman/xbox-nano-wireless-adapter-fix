"""xdongle - user-mode driver for the Xbox Wireless Adapter for Windows.

Run:  python -m xdongle [--debug] [--trace-input]
The adapter must be bound to WinUSB (Zadig) instead of Microsoft's driver.
"""

import argparse
import glob
import hashlib
import logging
import logging.handlers
import os
import shutil
import sys
import time

from .usbdev import DeviceGone, UsbDevice

log = logging.getLogger("xdongle")

PKG_DIR = os.path.dirname(os.path.abspath(__file__))
FW_DIR = os.path.join(PKG_DIR, "firmware")
FW_NAME = "FW_ACC_00U.bin"
# firmware for 045e:02fe from Microsoft's mt7612us_rl driver package (same file xone uses)
FW_SHA256 = {0x02FE: "48084d9fa53b9bb04358f3bb127b7495dc8f7bb0b3ca1437bd24ef2b6eabdf66"}


def find_firmware(pid, override=None):
    if override:
        with open(override, "rb") as f:
            return f.read()
    expected = FW_SHA256.get(pid)
    local = os.path.join(FW_DIR, f"{pid:04x}_{FW_NAME}")
    candidates = [local] + sorted(glob.glob(os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"), "System32", "DriverStore", "FileRepository",
        "mt7612us_rl.inf_*", FW_NAME)))
    for path in candidates:
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as f:
            data = f.read()
        digest = hashlib.sha256(data).hexdigest()
        if expected and digest != expected:
            log.debug("skipping %s (sha256 %s)", path, digest)
            continue
        if path != local:
            os.makedirs(FW_DIR, exist_ok=True)
            shutil.copyfile(path, local)
            log.info("Copied dongle firmware from %s", path)
        return data
    raise SystemExit(f"Dongle firmware {FW_NAME} for {pid:04x} not found. "
                     f"Pass --firmware PATH.")


def setup_logging(args):
    level = logging.DEBUG if args.debug else logging.INFO
    fmt = logging.Formatter("%(asctime)s.%(msecs)03d %(levelname).1s %(name)s: %(message)s",
                            "%H:%M:%S")
    root = logging.getLogger()
    root.setLevel(level)
    if sys.stdout is not None:          # None when started via pythonw (no console)
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        root.addHandler(sh)
    if args.log_file:
        fh = logging.handlers.RotatingFileHandler(args.log_file, maxBytes=5_000_000,
                                                  backupCount=2, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
    logging.getLogger("xdongle.input").setLevel(logging.DEBUG if args.trace_input
                                                else logging.INFO)


def main():
    ap = argparse.ArgumentParser(prog="xdongle", description=__doc__.splitlines()[1])
    ap.add_argument("--debug", action="store_true", help="verbose protocol logging")
    ap.add_argument("--trace-input", action="store_true", help="log every input report")
    ap.add_argument("--log-file", default=os.path.join(os.path.dirname(PKG_DIR), "xdongle.log"))
    ap.add_argument("--firmware", help="path to FW_ACC_00U.bin")
    ap.add_argument("--no-pair-on-start", action="store_true",
                    help="don't open the 60 s reconnect window at startup")
    ap.add_argument("--mac", help="override dongle MAC address, e.g. 62:45:bd:12:34:56")
    args = ap.parse_args()
    setup_logging(args)

    # single instance: a second copy could not claim the dongle anyway
    import ctypes
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    _mutex = kernel32.CreateMutexW(None, False, "Local\\xdongle-user-mode-driver")
    if kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        log.error("xdongle is already running; exiting.")
        return 1
    # Above-normal priority keeps input delivery under 1 ms even when a game saturates every
    # CPU core (measured: worst case 19 ms at normal priority vs 0.4 ms; tests/latency_bench.py).
    # xdongle is idle almost all the time, so this costs other programs nothing noticeable.
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.SetPriorityClass(ctypes.c_void_p(kernel32.GetCurrentProcess()),
                              0x8000)  # ABOVE_NORMAL_PRIORITY_CLASS

    from .dongle import Dongle
    from .vpad import VirtualPad

    override_mac = bytes.fromhex(args.mac.replace(":", "")) if args.mac else None
    waiting_logged = False
    while True:
        try:
            dev = UsbDevice.open()
        except RuntimeError as e:
            log.error("%s", e)
            time.sleep(5)
            continue
        if dev is None:
            if not waiting_logged:
                log.info("Waiting for the Xbox Wireless Adapter (WinUSB driver)...")
                waiting_logged = True
            time.sleep(2)
            continue
        waiting_logged = False
        firmware = find_firmware(dev.pid, args.firmware)
        dongle = Dongle(dev, firmware, VirtualPad, pair_on_start=not args.no_pair_on_start,
                        override_mac=override_mac)
        try:
            dongle.init()
            log.info("Ready. Press the button on the dongle to pair a new controller.")
            dongle.run()
        except DeviceGone as e:
            log.warning("Adapter went away (%s); reconnecting...", e)
            time.sleep(1)
        except KeyboardInterrupt:
            log.info("Shutting down...")
            try:
                dongle.shutdown()
            finally:
                dev.close()
            return 0
        except Exception:
            log.exception("Fatal error; restarting in 3 s")
            try:
                dongle.shutdown()
            except Exception:
                pass
            time.sleep(3)
        try:
            dev.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())

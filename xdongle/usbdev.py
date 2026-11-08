"""USB transport for the Xbox Wireless Adapter (MT76x2U based) via libusb/WinUSB.

Reads from both bulk IN endpoints with several queued async transfers (like URBs in
the Linux driver) and hands every completed buffer to a callback. Writes and control
transfers are synchronous.
"""

import logging
import struct
import threading
import time

import usb1

log = logging.getLogger("xdongle.usb")

VID_MICROSOFT = 0x045E
# Only the current adapter (02FE) is tested. The older one (02E6) needs different firmware.
SUPPORTED_PIDS = (0x02FE,)

EP_OUT = 0x04          # bulk OUT (commands + WLAN frames)
EP_IN_WLAN = 0x84      # bulk IN, received 802.11 frames
EP_IN_CMD = 0x85       # bulk IN, MCU events / command responses

# buffer sizes are multiples of 512 (USB2 bulk max packet size)
LEN_CMD_BUF = 0x0800
LEN_WLAN_BUF = 0x8400
NUM_IN_TRANSFERS = 8

USB_TIMEOUT_MS = 1000


class DeviceGone(Exception):
    """The dongle disappeared from the bus (unplugged or re-enumerating)."""


class UsbDevice:
    def __init__(self, ctx, handle, pid):
        self.ctx = ctx
        self.handle = handle
        self.pid = pid
        self._transfers = []
        self._event_thread = None
        self._running = False
        self._on_buffer = None
        self._on_gone = None
        self.gone = False
        self._write_lock = threading.Lock()

    # ------------------------------------------------------------------ open/close
    @classmethod
    def open(cls, pid=None):
        ctx = usb1.USBContext()
        ctx.open()
        try:
            for dev in ctx.getDeviceIterator(skip_on_error=True):
                if dev.getVendorID() != VID_MICROSOFT:
                    continue
                if dev.getProductID() not in SUPPORTED_PIDS:
                    continue
                if pid is not None and dev.getProductID() != pid:
                    continue
                try:
                    handle = dev.open()
                except usb1.USBErrorAccess as e:
                    raise RuntimeError(
                        f"Adapter {VID_MICROSOFT:04x}:{dev.getProductID():04x} is in use by another "
                        f"program (another xdongle instance?)") from e
                except usb1.USBError as e:
                    raise RuntimeError(
                        f"Found adapter {VID_MICROSOFT:04x}:{dev.getProductID():04x} but could not "
                        f"open it ({e}). Is the WinUSB driver installed for it (Zadig)?") from e
                try:
                    handle.claimInterface(0)
                except usb1.USBError as e:
                    handle.close()
                    raise RuntimeError(f"Could not claim the adapter's interface: {e}") from e
                log.info("Opened adapter %04x:%04x (bus %d, address %d)", VID_MICROSOFT,
                         dev.getProductID(), dev.getBusNumber(), dev.getDeviceAddress())
                return cls(ctx, handle, dev.getProductID())
        except Exception:
            ctx.close()
            raise
        ctx.close()
        return None

    def close(self):
        self.stop_reading()
        try:
            self.handle.releaseInterface(0)
        except usb1.USBError:
            pass
        try:
            self.handle.close()
        except usb1.USBError:
            pass
        try:
            self.ctx.close()
        except Exception:
            pass

    # ------------------------------------------------------------------ sync I/O
    def _check(self, e):
        if isinstance(e, usb1.USBErrorNoDevice) or isinstance(e, usb1.USBErrorIO) and self.gone:
            self.gone = True
            raise DeviceGone(str(e)) from e
        raise e

    def control_in(self, request, value, index, length):
        try:
            return bytes(self.handle.controlRead(
                usb1.TYPE_VENDOR | usb1.RECIPIENT_DEVICE, request, value, index, length,
                timeout=USB_TIMEOUT_MS))
        except usb1.USBError as e:
            self._check(e)

    def control_out(self, request, value, index, data=b""):
        try:
            return self.handle.controlWrite(
                usb1.TYPE_VENDOR | usb1.RECIPIENT_DEVICE, request, value, index, data,
                timeout=USB_TIMEOUT_MS)
        except usb1.USBError as e:
            self._check(e)

    def bulk_write(self, data, ep=EP_OUT):
        with self._write_lock:
            try:
                n = self.handle.bulkWrite(ep, data, timeout=USB_TIMEOUT_MS)
            except usb1.USBError as e:
                self._check(e)
            if n != len(data):
                raise OSError(f"short bulk write: {n}/{len(data)}")
            return n

    # ------------------------------------------------------------------ async reads
    def start_reading(self, on_buffer, on_gone):
        """on_buffer(endpoint, bytes) is called from the libusb event thread."""
        self._on_buffer = on_buffer
        self._on_gone = on_gone
        self._running = True
        for ep, size in ((EP_IN_CMD, LEN_CMD_BUF), (EP_IN_WLAN, LEN_WLAN_BUF)):
            for _ in range(NUM_IN_TRANSFERS):
                t = self.handle.getTransfer()
                t.setBulk(ep, size, callback=self._completed, user_data=ep, timeout=0)
                t.submit()
                self._transfers.append(t)
        self._event_thread = threading.Thread(target=self._event_loop, name="usb-events",
                                              daemon=True)
        self._event_thread.start()

    def _completed(self, t):
        status = t.getStatus()
        if status == usb1.TRANSFER_COMPLETED:
            n = t.getActualLength()
            if n:
                try:
                    self._on_buffer(t.getUserData(), bytes(t.getBuffer()[:n]))
                except Exception:
                    log.exception("buffer handler failed")
        elif status == usb1.TRANSFER_NO_DEVICE:
            if not self.gone:
                self.gone = True
                if self._on_gone:
                    self._on_gone()
            return
        elif status == usb1.TRANSFER_CANCELLED:
            return
        else:
            log.debug("transfer on ep %02x finished with status %d", t.getUserData(), status)
        if self._running and not self.gone:
            try:
                t.submit()
            except usb1.USBErrorNoDevice:
                self.gone = True
                if self._on_gone:
                    self._on_gone()
            except usb1.USBError as e:
                log.warning("resubmit on ep %02x failed: %s", t.getUserData(), e)

    def _event_loop(self):
        while self._running:
            try:
                self.ctx.handleEventsTimeout(tv=0.1)
            except usb1.USBErrorInterrupted:
                continue
            except usb1.USBError as e:
                log.debug("event loop error: %s", e)
                time.sleep(0.05)

    def stop_reading(self):
        if not self._running:
            return
        self._running = False
        for t in self._transfers:
            try:
                if t.isSubmitted():
                    t.cancel()
            except usb1.USBError:
                pass
        # let cancellations complete
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline and any(t.isSubmitted() for t in self._transfers):
            try:
                self.ctx.handleEventsTimeout(tv=0.05)
            except usb1.USBError:
                break
        if self._event_thread:
            self._event_thread.join(timeout=1.0)
        self._transfers = []


def le32(v):
    return struct.pack("<I", v & 0xFFFFFFFF)

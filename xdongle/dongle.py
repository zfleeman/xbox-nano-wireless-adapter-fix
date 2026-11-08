"""Dongle logic: receive path, wireless client management, pairing, event loop.

Port of xone's transport/dongle.c (GPL-2.0-or-later). All protocol work happens on one
worker thread (Dongle.run); USB completions and ViGEm callbacks only enqueue work.
"""

import heapq
import itertools
import logging
import queue
import struct
import time

from . import gip
from . import mt76 as M
from .mt76 import BIT, FIELD_GET, GENMASK, Mt76, Mt76Error
from .usbdev import DeviceGone

log = logging.getLogger("xdongle.dongle")

MAX_CLIENTS = 16
PAIRING_TIMEOUT = 60.0
PAIR_SCAN_INTERVAL = 2.0
POWER_OFF_TIMEOUT = 3.0
DRIVER_PROBE_DELAY = 0.7     # xone waits before probing a freshly identified client

QUEUE_DATA = 0x00

EVT_BUTTON = 0x04
EVT_PACKET_RX = 0x0C
EVT_CLIENT_LOST = 0x0E

MT_RX_FCE_INFO_CMD_SEQ = GENMASK(19, 16)
MT_RX_FCE_INFO_EVT_TYPE = GENMASK(23, 20)
MT_RX_FCE_INFO_D_PORT = GENMASK(29, 27)
MT_RXINFO_L2PAD = BIT(14)
MT_RXWI_CTL_WCID = GENMASK(7, 0)
MT_RXWI_CTL_MPDU_LEN = GENMASK(29, 16)
RXWI_LEN = 32

FCTL_FTYPE_STYPE = 0x00FC


def ieee80211_hdrlen(fc):
    ftype = fc & 0x000C
    if ftype == M.IEEE80211_FTYPE_DATA:
        hl = 30 if (fc & 0x0300) == 0x0300 else 24
        if fc & 0x0080:                  # QoS
            hl += 2
            if fc & 0x8000:              # +HTC
                hl += 4
        return hl
    if ftype == M.IEEE80211_FTYPE_MGMT:
        return 24 + (4 if fc & 0x8000 else 0)
    if ftype == 0x0004:                  # control
        stype = fc & 0x00F0
        return 10 if stype in (0x00C0, 0x00D0) else 16
    return 24


def valid_unicast(addr):
    return any(addr) and not (addr[0] & 0x01)


class WirelessClient:
    def __init__(self, dongle, wcid, address):
        self.dongle = dongle
        self.wcid = wcid
        self.address = bytes(address)
        self.encryption_enabled = False
        self.adapter = gip.GipAdapter(f"pad{wcid}", self.send_buffer, self.set_key,
                                      dongle.make_driver)

    def send_buffer(self, buf):
        self.dongle.send_client_packet(self, buf)

    def set_key(self, key):
        log.debug("[pad%d] installing link key", self.wcid)
        self.dongle.mt.set_client_key(self.wcid, key)


class Dongle:
    def __init__(self, usb, firmware, vpad_factory, pair_on_start=True, override_mac=None):
        self.usb = usb
        self.mt = Mt76(usb)
        self.firmware = firmware
        self.vpad_factory = vpad_factory
        self.pair_on_start = pair_on_start
        self.override_mac = override_mac
        self.queue = queue.Queue()
        self.timers = []
        self._timer_seq = itertools.count()
        self.clients = [None] * MAX_CLIENTS
        self.pairing = False
        self.pairing_deadline = None
        self.next_scan = 0.0
        self.last_wlan_rx = 0.0
        self.pairing_scan_idx = 0
        self.ready = False
        self.stopping = False

    # ---------------------------------------------------------------- threading helpers
    def post(self, fn, delay=0.0):
        """Run fn on the worker thread (thread-safe)."""
        self.queue.put(("call", fn, delay))

    def _schedule(self, delay, fn):
        heapq.heappush(self.timers, (time.monotonic() + delay, next(self._timer_seq), fn))

    def _on_usb_buffer(self, ep, data):
        self.queue.put(("usb", data, 0))

    def _on_usb_gone(self):
        self.queue.put(("gone", None, 0))

    # ---------------------------------------------------------------- bring-up
    def init(self):
        for attempt in range(5):
            try:
                mode = self.mt.load_firmware(self.firmware)
                break
            except Mt76Error as e:
                log.warning("firmware load attempt %d failed: %s", attempt + 1, e)
                time.sleep(1)
        else:
            raise Mt76Error("could not load firmware")
        log.info("Firmware ready (%s start)", mode)

        self.usb.start_reading(self._on_usb_buffer, self._on_usb_gone)

        for attempt in range(3):
            try:
                self.mt.init_radio(self.override_mac)
                break
            except Mt76Error as e:
                log.warning("radio init attempt %d failed: %s", attempt + 1, e)
                time.sleep(0.5)
        else:
            raise Mt76Error("could not initialise radio")
        self.ready = True
        log.info("Radio ready on channel %d", self.mt.channel.index)
        if self.pair_on_start:
            # lets already-paired controllers find us again
            self.toggle_pairing(True)
        else:
            self.mt.set_led_mode(M.LED_OFF)

    # ---------------------------------------------------------------- main loop
    def run(self):
        while not self.stopping:
            timeout = 0.25
            if self.timers:
                timeout = max(0.0, min(timeout, self.timers[0][0] - time.monotonic()))
            try:
                kind, payload, delay = self.queue.get(timeout=timeout)
            except queue.Empty:
                kind = None
            if kind == "usb":
                self._process_message(payload)
            elif kind == "call":
                if delay:
                    self._schedule(delay, payload)
                else:
                    self._safe(payload)
            elif kind == "gone":
                raise DeviceGone("adapter removed")
            self._run_timers()
            self._pairing_tick()

    def _run_timers(self):
        now = time.monotonic()
        while self.timers and self.timers[0][0] <= now:
            _, _, fn = heapq.heappop(self.timers)
            self._safe(fn)

    def _safe(self, fn):
        try:
            fn()
        except DeviceGone:
            raise
        except Exception:
            log.exception("handler failed")

    def shutdown(self):
        """Power off connected controllers and quiet the radio."""
        self.stopping = True
        if not self.ready or self.usb.gone:
            return
        any_on = False
        for c in self.clients:
            if c:
                any_on = True
                try:
                    c.adapter.power_off()
                except Exception:
                    pass
        deadline = time.monotonic() + (POWER_OFF_TIMEOUT if any_on else 0)
        while any(self.clients) and time.monotonic() < deadline:
            try:
                kind, payload, _ = self.queue.get(timeout=0.1)
                if kind == "usb":
                    self._process_message(payload)
            except queue.Empty:
                pass
            except Exception:
                break
        for c in self.clients:
            if c:
                c.adapter.destroy()
        try:
            if self.pairing:
                self.mt.set_pairing(False)
            self.mt.set_led_mode(M.LED_OFF)
        except Exception:
            pass

    # ---------------------------------------------------------------- pairing
    def toggle_pairing(self, enable, timeout=PAIRING_TIMEOUT):
        if self.pairing == enable:
            if enable:
                self.pairing_deadline = time.monotonic() + timeout
            return
        self.mt.set_pairing(enable)
        if enable:
            led = M.LED_BLINK
        elif any(self.clients):
            led = M.LED_ON
        else:
            led = M.LED_OFF
        self.mt.set_led_mode(led)
        self.pairing = enable
        now = time.monotonic()
        if enable:
            self.last_wlan_rx = now
            self.pairing_deadline = now + timeout
            self.next_scan = now + PAIR_SCAN_INTERVAL
            self.pairing_scan_idx = self._channel_idx()
            log.info("Pairing/reconnect window open for %d s", timeout)
        else:
            self.pairing_deadline = None
            log.info("Pairing window closed")

    def _channel_idx(self):
        for i, c in enumerate(self.mt.channels):
            if self.mt.channel and c.index == self.mt.channel.index:
                return i
        return 0

    def _pairing_tick(self):
        if not self.pairing or not self.ready:
            return
        now = time.monotonic()
        if now >= self.pairing_deadline:
            self._safe(lambda: self.toggle_pairing(False))
            return
        if now < self.next_scan:
            return
        self.next_scan = now + PAIR_SCAN_INTERVAL
        # keep the channel stable while anyone is connected or talking to us
        if any(self.clients) or now < self.last_wlan_rx + PAIR_SCAN_INTERVAL:
            return
        nxt = (self.pairing_scan_idx + 1) % len(self.mt.channels)
        chan = self.mt.channels[nxt]
        try:
            self.mt.switch_channel(chan)
            log.debug("pairing scan: channel %d -> %d", self.mt.channel.index, chan.index)
            self.mt.channel = chan
        except DeviceGone:
            raise
        except Exception as e:
            log.debug("channel switch failed: %s", e)
        self.pairing_scan_idx = nxt
        self.last_wlan_rx = now

    # ---------------------------------------------------------------- clients
    def make_driver(self, client):
        """Called by GIP when a client identified itself. Probes after a short delay."""
        if client.id != 0:
            log.info("[%s] attachment client ignored (classes %s)", client.name, client.classes)
            return
        if gip.CLASS_GAMEPAD not in (client.classes or []):
            if client.vendor != 0x045E:
                log.info("[%s] not a gamepad, ignored (classes %s)", client.name, client.classes)
                return
            log.warning("[%s] no gamepad class advertised; treating it as a gamepad anyway",
                        client.name)

        def probe():
            if client.adapter.clients.get(client.id) is not client or client.driver:
                return
            client.driver = gip.Gamepad(client, self.vpad_factory, self.post)
        self._schedule(DRIVER_PROBE_DELAY, probe)
        return

    def _add_client(self, addr):
        for c in self.clients:
            if c and c.address == addr:
                return
        try:
            idx = self.clients.index(None)
        except ValueError:
            log.error("all %d client slots in use", MAX_CLIENTS)
            return
        wcid = idx + 1
        self.mt.associate_client(wcid, addr)
        if not self.pairing:
            self.mt.set_led_mode(M.LED_ON)
        self.clients[idx] = WirelessClient(self, wcid, addr)
        log.info("Controller %s connected (slot %d)", bytes(addr).hex(":"), wcid)

    def _remove_client(self, wcid):
        if not 1 <= wcid <= MAX_CLIENTS:
            return
        c = self.clients[wcid - 1]
        if not c:
            return
        self.clients[wcid - 1] = None
        log.info("Controller %s disconnected (slot %d)", c.address.hex(":"), wcid)
        c.adapter.destroy()
        try:
            self.mt.remove_client(wcid)
        except DeviceGone:
            raise
        except Exception as e:
            log.error("remove client failed: %s", e)
        if not any(self.clients) and not self.pairing:
            self.mt.set_led_mode(M.LED_OFF)

    def _pair_client(self, addr):
        log.info("Pairing with controller %s", bytes(addr).hex(":"))
        self.mt.pair_client(addr)
        self.toggle_pairing(False)

    def _enable_encryption(self, wcid):
        c = self.clients[wcid - 1] if 1 <= wcid <= MAX_CLIENTS else None
        if not c:
            return
        self.mt.send_client_command(wcid, c.address, M.CLIENT_ENABLE_ENCRYPTION, b"\0\0")
        c.encryption_enabled = True
        log.info("[pad%d] link encryption enabled", wcid)

    def send_client_packet(self, client, buf, queue_id=QUEUE_DATA):
        fc = M.IEEE80211_FTYPE_DATA | M.IEEE80211_STYPE_QOS_DATA | M.IEEE80211_FCTL_FROMDS
        if client.encryption_enabled:
            fc |= M.IEEE80211_FCTL_PROTECTED
        qos_hdr = (struct.pack("<HH", fc, 144) + client.address + self.mt.address +
                   self.mt.address + b"\0\0" + b"\0\0")         # seq ctrl + QoS ctrl
        data = bytes([0, 0, queue_id, client.wcid - 1, 0, 0, 0, 0])
        tw = M.default_txwi(client.wcid - 1, len(qos_hdr) + len(buf))
        self.usb.bulk_write(M.prep_command(data + tw + qos_hdr + b"\0\0" + bytes(buf), 0))

    # ---------------------------------------------------------------- receive path
    def _process_message(self, buf):
        if len(buf) < M.MT_CMD_HDR_LEN * 2:
            return
        info = struct.unpack_from("<I", buf, 0)[0]
        port = FIELD_GET(MT_RX_FCE_INFO_D_PORT, info)
        if FIELD_GET(MT_RX_FCE_INFO_CMD_SEQ, info) == 0x01:
            return      # command response
        data = buf[4:-4]
        try:
            if port == M.MT_WLAN_PORT:
                return self._process_wlan(data)
            if port != M.MT_CPU_RX_PORT:
                return
            evt = FIELD_GET(MT_RX_FCE_INFO_EVT_TYPE, info)
            if evt == EVT_BUTTON:
                log.info("Dongle button pressed")
                if self.ready:
                    self.toggle_pairing(True)
            elif evt == EVT_PACKET_RX:
                self._process_wlan(data)
            elif evt == EVT_CLIENT_LOST:
                if data:
                    log.debug("client lost: wcid %d", data[0])
                    self._remove_client(data[0])
        except DeviceGone:
            raise
        except Exception:
            log.exception("failed to process message %s", bytes(buf[:96]).hex())

    def _process_wlan(self, data):
        if len(data) < RXWI_LEN:
            return
        rxinfo, ctl = struct.unpack_from("<II", data, 0)
        frame = data[RXWI_LEN:]
        if len(frame) < 2:
            return
        fc = struct.unpack_from("<H", frame, 0)[0]
        hdr_len = ieee80211_hdrlen(fc)
        if rxinfo & MT_RXINFO_L2PAD:      # 2 bytes of padding after the 802.11 header
            if len(frame) < hdr_len + 2:
                return
            frame = frame[:hdr_len] + frame[hdr_len + 2:]
        mpdu_len = FIELD_GET(MT_RXWI_CTL_MPDU_LEN, ctl)
        if mpdu_len > len(frame):
            return
        frame = frame[:mpdu_len]
        self._process_frame(frame, hdr_len, FIELD_GET(MT_RXWI_CTL_WCID, ctl))

    def _process_frame(self, frame, hdr_len, wcid):
        if len(frame) < hdr_len or hdr_len < 24:
            return
        fc = struct.unpack_from("<H", frame, 0)[0]
        addr2 = bytes(frame[10:16])
        payload = frame[hdr_len:]
        kind = fc & FCTL_FTYPE_STYPE
        if not self.ready:
            return
        if kind == M.IEEE80211_FTYPE_DATA | M.IEEE80211_STYPE_QOS_DATA:
            if not 1 <= wcid <= MAX_CLIENTS:
                return
            c = self.clients[wcid - 1]
            if c:
                if self.pairing:
                    self.last_wlan_rx = time.monotonic()
                try:
                    c.adapter.process_buffer(bytes(payload))
                except DeviceGone:
                    raise
                except Exception as e:
                    log.warning("[pad%d] GIP error: %s (data %s)", wcid, e, bytes(payload).hex())
        elif kind == M.IEEE80211_FTYPE_MGMT | M.IEEE80211_STYPE_ASSOC_REQ:
            if valid_unicast(addr2):
                if self.pairing:
                    self.last_wlan_rx = time.monotonic()
                self._add_client(addr2)
        elif kind == M.IEEE80211_FTYPE_MGMT | M.IEEE80211_STYPE_DISASSOC:
            self._remove_client(wcid)
        elif kind == M.IEEE80211_FTYPE_MGMT | M.XONE_MT_WLAN_RESERVED:
            if len(payload) < 2 or payload[0] != M.XONE_MT_WLAN_RESERVED:
                return
            cmd = payload[1]
            if cmd == M.CLIENT_PAIR_REQ:
                if self.pairing:
                    self.last_wlan_rx = time.monotonic()
                self._pair_client(addr2)
            elif cmd == M.CLIENT_ENABLE_ENCRYPTION:
                if 1 <= wcid <= MAX_CLIENTS:
                    self._enable_encryption(wcid)
            else:
                log.debug("client command 0x%02x from %s", cmd, addr2.hex(":"))

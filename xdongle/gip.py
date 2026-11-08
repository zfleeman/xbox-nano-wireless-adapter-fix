"""Game Input Protocol (GIP) - the protocol Xbox One/Series accessories speak.

Port of xone's bus/protocol.c and driver/gamepad.c (GPL-2.0-or-later), simplified to what
a wireless gamepad needs. One GipAdapter exists per wirelessly connected controller; it can
host several GIP clients (id 0 = the controller itself, others = attachments).
"""

import logging
import struct
import uuid

from .auth import GipAuth

log = logging.getLogger("xdongle.gip")
log_in = logging.getLogger("xdongle.input")

HDR_MIN_LENGTH = 3
PKT_MAX_LENGTH = 58
PKT_COALESCE_COUNT = 5
CHUNK_BUF_MAX_LENGTH = 0xFFFF

# core commands (sent with OPT_INTERNAL)
CMD_ACKNOWLEDGE = 0x01
CMD_ANNOUNCE = 0x02
CMD_STATUS = 0x03
CMD_IDENTIFY = 0x04
CMD_POWER = 0x05
CMD_AUTHENTICATE = 0x06
CMD_VIRTUAL_KEY = 0x07
CMD_AUDIO_CONTROL = 0x08
CMD_LED = 0x0A
CMD_HID_REPORT = 0x0B
CMD_FIRMWARE = 0x0C
CMD_EXTENDED = 0x1E
CMD_AUDIO_SAMPLES = 0x60
# client commands
CMD_RUMBLE = 0x09
CMD_INPUT = 0x20

OPT_ACKNOWLEDGE = 0x10
OPT_INTERNAL = 0x20
OPT_CHUNK_START = 0x40
OPT_CHUNK = 0x80
HDR_CLIENT_ID = 0x0F

PWR_ON, PWR_SLEEP, PWR_OFF, PWR_RESET = 0x00, 0x01, 0x04, 0x07
LED_ON = 0x01
LED_BRIGHTNESS_DEFAULT = 20
STATUS_CONNECTED = 0x80
VKEY_LEFT_WIN = 0x5B
EXT_GET_SERIAL_NUMBER = 0x04

CLASS_GAMEPAD = "Windows.Xbox.Input.Gamepad"

BATTERY_TYPES = {0: "none", 1: "standard", 2: "kit"}
BATTERY_LEVELS = {0: "low", 1: "normal", 2: "high", 3: "full"}

CMD_NAMES = {
    CMD_ACKNOWLEDGE: "ACK", CMD_ANNOUNCE: "ANNOUNCE", CMD_STATUS: "STATUS",
    CMD_IDENTIFY: "IDENTIFY", CMD_POWER: "POWER", CMD_AUTHENTICATE: "AUTH",
    CMD_VIRTUAL_KEY: "VKEY", CMD_AUDIO_CONTROL: "AUDIO_CTRL", CMD_LED: "LED",
    CMD_HID_REPORT: "HID_REPORT", CMD_FIRMWARE: "FIRMWARE", CMD_EXTENDED: "EXTENDED",
    CMD_AUDIO_SAMPLES: "AUDIO", CMD_RUMBLE: "RUMBLE", CMD_INPUT: "INPUT",
}


class GipError(Exception):
    pass


# ------------------------------------------------------------------- header coding
class Header:
    __slots__ = ("chunk_offset", "command", "options", "packet_length", "sequence")

    def __init__(self, command=0, options=0, sequence=0, packet_length=0, chunk_offset=0):
        self.command, self.options, self.sequence = command, options, sequence
        self.packet_length, self.chunk_offset = packet_length, chunk_offset

    def copy(self):
        return Header(self.command, self.options, self.sequence, self.packet_length,
                      self.chunk_offset)

    def __repr__(self):
        return (f"<{CMD_NAMES.get(self.command, hex(self.command))} opt=0x{self.options:02x} "
                f"seq={self.sequence} len={self.packet_length} off={self.chunk_offset}>")


def encode_varint(val):
    out = bytearray()
    for _ in range(4):
        b = val & 0xFF
        if val > 0x7F:
            b |= 0x80
        out.append(b & 0xFF)
        val >>= 7
        if not val:
            break
    return bytes(out)


def decode_varint(data):
    val = 0
    i = 0
    while i < 4 and i < len(data):
        val |= (data[i] & 0x7F) << (i * 7)
        if not data[i] & 0x80:
            break
        i += 1
    return val, i + 1


def actual_header_length(hdr):
    length = HDR_MIN_LENGTH
    pkt_len = hdr.packet_length
    while True:
        length += 1
        pkt_len >>= 7
        if not pkt_len:
            break
    if hdr.options & OPT_CHUNK:
        off = hdr.chunk_offset
        while off:
            length += 1
            off >>= 7
    return length


def header_length(hdr):
    n = actual_header_length(hdr)
    return n + (n % 2)


def encode_header(hdr):
    buf = bytearray([hdr.command, hdr.options, hdr.sequence])
    buf += encode_varint(hdr.packet_length)
    if actual_header_length(hdr) % 2:      # header length must be even
        buf[-1] |= 0x80
        buf.append(0)
    if hdr.options & OPT_CHUNK and hdr.chunk_offset:
        buf += encode_varint(hdr.chunk_offset)
    return bytes(buf)


def decode_header(data):
    hdr = Header(data[0], data[1], data[2])
    pos = 3
    hdr.packet_length, n = decode_varint(data[pos:])
    pos += n
    if hdr.options & OPT_CHUNK:
        hdr.chunk_offset, n = decode_varint(data[pos:])
        pos += n
    return hdr, pos


class ChunkBuffer:
    __slots__ = ("data", "header", "length")

    def __init__(self, hdr):
        if hdr.chunk_offset > CHUNK_BUF_MAX_LENGTH:
            raise GipError("chunked packet too large")
        self.header = hdr.copy()
        self.header.options &= ~(OPT_ACKNOWLEDGE | OPT_CHUNK_START)
        self.length = hdr.chunk_offset
        self.data = bytearray(self.length)


# ------------------------------------------------------------------- adapter / client
class GipAdapter:
    """GIP endpoint for one wireless controller.

    send_buffer(bytes) transmits a raw GIP buffer; set_key(bytes) installs the link key;
    make_driver(client) returns a driver object for an identified client (or None)."""

    def __init__(self, name, send_buffer, set_key, make_driver):
        self.name = name
        self.send_buffer = send_buffer
        self.set_key = set_key
        self.make_driver = make_driver
        self.data_sequence = 0
        self.clients = {}

    def get_client(self, cid):
        c = self.clients.get(cid)
        if c is None:
            c = GipClient(self, cid)
            self.clients[cid] = c
            log.debug("[%s] new GIP client %d", self.name, cid)
        return c

    def remove_client(self, cid):
        c = self.clients.pop(cid, None)
        if c:
            c.destroy()

    def destroy(self):
        for cid in list(self.clients):
            self.remove_client(cid)

    def power_off(self):
        c = self.clients.get(0)
        if c:
            c.set_power_mode(PWR_OFF)

    def process_buffer(self, data):
        while len(data) > HDR_MIN_LENGTH:
            hdr, hdr_len = decode_header(data)
            if len(data) < hdr_len + hdr.packet_length:
                raise GipError(f"truncated packet {hdr!r}")
            client = self.get_client(hdr.options & HDR_CLIENT_ID)
            payload = data[hdr_len:hdr_len + hdr.packet_length]
            client.process_pkt(hdr, payload)
            data = data[hdr_len + hdr.packet_length:]


class GipClient:
    def __init__(self, adapter, cid):
        self.adapter = adapter
        self.id = cid
        self.name = f"{adapter.name}.{cid}"
        self.vendor = self.product = self.version = 0
        self.classes = None
        self.interfaces = []
        self.chunk_buf_in = None    # outgoing chunked packet (host -> device)
        self.chunk_buf_out = None   # incoming chunked packet (device -> host)
        self.driver = None

    def destroy(self):
        if self.driver:
            try:
                self.driver.remove()
            except Exception:
                log.exception("[%s] driver removal failed", self.name)
            self.driver = None

    # ---------------------------------------------------------------- sending
    def _send_simple(self, hdr, data):
        adap = self.adapter
        while not hdr.sequence:
            hdr.sequence = adap.data_sequence
            adap.data_sequence = (adap.data_sequence + 1) & 0xFF
        buf = encode_header(hdr)
        if len(buf) != header_length(hdr):
            raise GipError("header length mismatch")
        if data:
            buf += bytes(data[:hdr.packet_length])
        if log.isEnabledFor(logging.DEBUG):
            log.debug("[%s] -> %r %s", self.name, hdr, bytes(data or b"")[:hdr.packet_length].hex())
        self.adapter.send_buffer(buf)

    def send_pkt(self, hdr, data=None):
        if hdr.packet_length <= PKT_MAX_LENGTH:
            return self._send_simple(hdr, data)
        # first chunk carries the total length as its offset
        hdr.options |= OPT_ACKNOWLEDGE | OPT_CHUNK_START | OPT_CHUNK
        hdr.chunk_offset = hdr.packet_length
        hdr.packet_length = PKT_MAX_LENGTH
        self._send_simple(hdr, data)
        if self.chunk_buf_in:
            log.warning("[%s] outgoing chunk buffer already in use", self.name)
        self.chunk_buf_in = ChunkBuffer(hdr)
        self.chunk_buf_in.data[:] = bytes(data[:hdr.chunk_offset])

    def _send_remaining_chunks(self, offset):
        buf = self.chunk_buf_in
        hdr = buf.header.copy()
        remaining = buf.length - offset
        count = PKT_COALESCE_COUNT
        while remaining and count:
            if remaining <= PKT_MAX_LENGTH:
                hdr.options |= OPT_ACKNOWLEDGE    # last chunk must be acknowledged
            hdr.packet_length = min(remaining, PKT_MAX_LENGTH)
            hdr.chunk_offset = buf.length - remaining
            self._send_simple(hdr, buf.data[hdr.chunk_offset:hdr.chunk_offset + hdr.packet_length])
            remaining -= hdr.packet_length
            count -= 1

    def acknowledge(self, ack):
        buf = self.chunk_buf_out
        length = ack.chunk_offset + ack.packet_length
        remaining = 0
        if ack.options & OPT_CHUNK and buf:
            remaining = buf.length - length
        pkt = struct.pack("<BBBH2xH", 0, ack.command, self.id | OPT_INTERNAL, length & 0xFFFF,
                          remaining & 0xFFFF)
        self.send_pkt(Header(CMD_ACKNOWLEDGE, self.id | OPT_INTERNAL, ack.sequence, len(pkt)), pkt)

    def send_internal(self, command, payload=b"", acknowledge=False):
        opts = self.id | OPT_INTERNAL | (OPT_ACKNOWLEDGE if acknowledge else 0)
        self.send_pkt(Header(command, opts, 0, len(payload)), payload)

    def set_power_mode(self, mode):
        self.send_internal(CMD_POWER, bytes([mode]))

    def set_led_mode(self, mode, brightness):
        self.send_internal(CMD_LED, bytes([0, mode, brightness]))

    def send_authenticate(self, payload, acknowledge):
        self.send_internal(CMD_AUTHENTICATE, payload, acknowledge)

    def send_rumble(self, payload):
        self.send_pkt(Header(CMD_RUMBLE, self.id, 0, len(payload)), payload)

    def request_serial_number(self):
        self.send_internal(CMD_EXTENDED, bytes([EXT_GET_SERIAL_NUMBER]))

    # ---------------------------------------------------------------- receiving
    def process_pkt(self, hdr, data):
        if hdr.options & OPT_CHUNK_START:
            self.chunk_buf_out = ChunkBuffer(hdr)
            hdr.chunk_offset = 0
        if hdr.options & OPT_CHUNK:
            return self._process_chunked(hdr, data)
        if hdr.options & OPT_ACKNOWLEDGE:
            self.acknowledge(hdr)
        return self._dispatch(hdr, data)

    def _process_chunked(self, hdr, data):
        buf = self.chunk_buf_out
        if buf is None:
            if not hdr.packet_length:
                return       # older gamepads send spurious completions
            raise GipError(f"[{self.name}] chunk without buffer {hdr!r}")
        if hdr.command != buf.header.command:
            raise GipError(f"[{self.name}] conflicting chunk {hdr!r}")
        end = hdr.chunk_offset + hdr.packet_length
        if buf.length < end:
            raise GipError(f"[{self.name}] chunk exceeds buffer {hdr!r}")
        if hdr.packet_length:
            if hdr.options & OPT_ACKNOWLEDGE or buf.length == end:
                self.acknowledge(hdr)
            buf.data[hdr.chunk_offset:end] = data
            return
        # empty chunk = transfer complete
        self.chunk_buf_out = None
        self._dispatch(hdr, bytes(buf.data))

    def _dispatch(self, hdr, data):
        cmd = hdr.command
        if hdr.options & OPT_INTERNAL:
            if cmd not in (CMD_ACKNOWLEDGE,) and log.isEnabledFor(logging.DEBUG):
                log.debug("[%s] <- %r %s", self.name, hdr, data.hex())
            handler = {
                CMD_ACKNOWLEDGE: self._on_acknowledge,
                CMD_ANNOUNCE: self._on_announce,
                CMD_STATUS: self._on_status,
                CMD_IDENTIFY: self._on_identify,
                CMD_AUTHENTICATE: self._on_authenticate,
                CMD_VIRTUAL_KEY: self._on_virtual_key,
                CMD_HID_REPORT: self._on_hid_report,
                CMD_EXTENDED: self._on_extended,
            }.get(cmd)
            if handler:
                return handler(data)
            log.debug("[%s] ignoring internal command 0x%02x", self.name, cmd)
            return
        if cmd == CMD_INPUT:
            if log_in.isEnabledFor(logging.DEBUG):
                log_in.debug("[%s] input %s", self.name, data.hex())
            if self.driver:
                self.driver.on_input(data)
        elif cmd == CMD_FIRMWARE:
            log.debug("[%s] firmware/extra packet %s", self.name, data.hex())
        else:
            log.debug("[%s] unknown client command %r %s", self.name, hdr, data.hex())

    def _on_acknowledge(self, data):
        if len(data) != 9:
            raise GipError("bad acknowledge length")
        buf = self.chunk_buf_in
        if buf is None:
            return
        _, command, _, length, _ = struct.unpack("<BBBH2xH", data)
        if command != buf.header.command:
            return
        if length < buf.length:
            return self._send_remaining_chunks(length)
        # all chunks sent: an empty chunk signals completion
        hdr = buf.header.copy()
        hdr.packet_length = 0
        hdr.chunk_offset = buf.length
        self.chunk_buf_in = None
        self._send_simple(hdr, None)

    def _on_announce(self, data):
        if len(data) != 28:
            raise GipError("bad announce length")
        addr = data[0:6]
        vid, pid = struct.unpack_from("<HH", data, 8)
        fw = struct.unpack_from("<4H", data, 12)
        hw = struct.unpack_from("<4H", data, 20)
        if not (self.vendor or self.product or self.version):
            self.vendor, self.product = vid, pid
            self.version = (fw[0] << 8) | fw[1]
        log.info("[%s] announce: %s vid=%04x pid=%04x fw=%s hw=%s", self.name, addr.hex(":"),
                 vid, pid, ".".join(map(str, fw)), ".".join(map(str, hw)))
        self.send_internal(CMD_IDENTIFY)   # request identification

    def _on_status(self, data):
        if len(data) < 4:
            raise GipError("bad status length")
        status = data[0]
        if not status & STATUS_CONNECTED:
            log.info("[%s] client reports disconnect", self.name)
            self.adapter.remove_client(self.id)
            return
        btype = (status >> 2) & 3
        blevel = status & 3
        if self.driver:
            self.driver.on_battery(btype, blevel)

    def _on_identify(self, data):
        if len(data) < 32:
            raise GipError("identify too short")
        if self.classes is not None:
            log.debug("[%s] already identified", self.name)
            return
        offs = struct.unpack_from("<8H", data, 16)
        (cmds_off, fw_off, audio_off, caps_out_off, caps_in_off, classes_off, intf_off,
         hid_off) = offs
        body = data[16:]

        def elem(off, item_len):
            if not off or len(body) < off + 1:
                return []
            count = body[off]
            start = off + 1
            if len(body) < start + count * item_len:
                raise GipError("identify element truncated")
            return [body[start + i * item_len:start + (i + 1) * item_len] for i in range(count)]

        classes = []
        if classes_off and len(body) > classes_off:
            count = body[classes_off]
            pos = classes_off + 1
            for _ in range(count):
                (slen,) = struct.unpack_from("<H", body, pos)
                pos += 2
                classes.append(body[pos:pos + slen].decode(errors="replace"))
                pos += slen
        self.classes = classes
        self.interfaces = [uuid.UUID(bytes_le=bytes(g)) for g in elem(intf_off, 16)]
        fw_versions = [struct.unpack("<HH", v) for v in elem(fw_off, 4)]
        hid_desc = elem(hid_off, 1)
        log.info("[%s] identify: classes=%s", self.name, classes)
        log.info("[%s] identify: interfaces=%s", self.name, [str(i) for i in self.interfaces])
        log.info("[%s] identify: firmware versions=%s, audio formats=%d, hid descriptor=%d bytes",
                 self.name, fw_versions, len(elem(audio_off, 2)), len(hid_desc))
        # the driver may be attached later (after a short probe delay)
        self.driver = self.adapter.make_driver(self)

    def _on_authenticate(self, data):
        if self.driver and hasattr(self.driver, "on_authenticate"):
            self.driver.on_authenticate(data)

    def _on_virtual_key(self, data):
        if len(data) != 2:
            raise GipError("bad virtual key length")
        down, key = data[0], data[1]
        if key == VKEY_LEFT_WIN and self.driver:
            self.driver.on_guide(bool(down))

    def _on_hid_report(self, data):
        log.info("[%s] HID report over GIP (%d bytes): %s", self.name, len(data), data.hex())

    def _on_extended(self, data):
        if len(data) >= 2 and data[0] == EXT_GET_SERIAL_NUMBER and data[1] == 0:
            log.info("[%s] serial number: %s", self.name,
                     data[2:].split(b"\0")[0].decode(errors="replace"))


# ------------------------------------------------------------------- gamepad driver
BTN_MENU, BTN_VIEW = 1 << 2, 1 << 3
BTN_A, BTN_B, BTN_X, BTN_Y = 1 << 4, 1 << 5, 1 << 6, 1 << 7
BTN_DPAD_U, BTN_DPAD_D, BTN_DPAD_L, BTN_DPAD_R = 1 << 8, 1 << 9, 1 << 10, 1 << 11
BTN_BUMPER_L, BTN_BUMPER_R, BTN_STICK_L, BTN_STICK_R = 1 << 12, 1 << 13, 1 << 14, 1 << 15

# XInput (XUSB) button bits
XUSB = {
    "DPAD_UP": 0x0001, "DPAD_DOWN": 0x0002, "DPAD_LEFT": 0x0004, "DPAD_RIGHT": 0x0008,
    "START": 0x0010, "BACK": 0x0020, "LEFT_THUMB": 0x0040, "RIGHT_THUMB": 0x0080,
    "LEFT_SHOULDER": 0x0100, "RIGHT_SHOULDER": 0x0200, "GUIDE": 0x0400,
    "A": 0x1000, "B": 0x2000, "X": 0x4000, "Y": 0x8000,
}
GIP_TO_XUSB = [
    (BTN_MENU, XUSB["START"]), (BTN_VIEW, XUSB["BACK"]),
    (BTN_A, XUSB["A"]), (BTN_B, XUSB["B"]), (BTN_X, XUSB["X"]), (BTN_Y, XUSB["Y"]),
    (BTN_DPAD_U, XUSB["DPAD_UP"]), (BTN_DPAD_D, XUSB["DPAD_DOWN"]),
    (BTN_DPAD_L, XUSB["DPAD_LEFT"]), (BTN_DPAD_R, XUSB["DPAD_RIGHT"]),
    (BTN_BUMPER_L, XUSB["LEFT_SHOULDER"]), (BTN_BUMPER_R, XUSB["RIGHT_SHOULDER"]),
    (BTN_STICK_L, XUSB["LEFT_THUMB"]), (BTN_STICK_R, XUSB["RIGHT_THUMB"]),
]

MOTOR_ALL = 0x0F
RUMBLE_MAX = 100


def rumble_packet(left, right):
    # unknown, motors, left trigger, right trigger, left, right, duration, delay, repeat
    return bytes([0, MOTOR_ALL, 0, 0, left, right, 0xFF, 0, 0xEB])


class Gamepad:
    """GIP gamepad -> virtual Xbox 360 controller."""

    def __init__(self, client, vpad_factory, post):
        self.client = client
        self.name = client.name
        self.post = post            # post(fn): run fn on the worker thread
        self.buttons = 0
        self.guide = False
        self.last_state = None
        self.vpad = None
        self.battery = None

        client.set_power_mode(PWR_ON)
        client.set_led_mode(LED_ON, LED_BRIGHTNESS_DEFAULT)
        self.auth = GipAuth(client.send_authenticate, self._on_key, client.name)
        try:
            self.auth.start()
        except Exception:
            log.exception("[%s] could not start authentication", self.name)
        # stop rumble (also required for some gamepads to start sending input)
        client.send_rumble(rumble_packet(0, 0))
        self.vpad = vpad_factory(self._on_rumble_request)
        log.info("[%s] gamepad ready (vid=%04x pid=%04x) -> virtual Xbox 360 controller",
                 self.name, client.vendor, client.product)

    def _on_key(self, key):
        self.client.adapter.set_key(key)

    def on_authenticate(self, data):
        if self.auth.completed or self.auth.failed:
            log.debug("[%s] auth packet after handshake ended: %s", self.name, data.hex())
            return
        try:
            self.auth.process(data)
        except Exception as e:
            # xone does not gate input on authentication either
            log.warning("[%s] authentication problem: %s (input continues)", self.name, e)
            self.auth.failed = True

    def on_battery(self, btype, level):
        state = (BATTERY_TYPES.get(btype, "?"), BATTERY_LEVELS.get(level, "?"))
        if state != self.battery:
            self.battery = state
            log.info("[%s] battery: %s, level %s", self.name, *state)

    def on_guide(self, down):
        self.guide = down
        self._push()

    def on_input(self, data):
        if len(data) < 14:
            return
        (self.buttons, lt, rt, lx, ly, rx, ry) = struct.unpack_from("<HHHhhhh", data, 0)
        self._state = (lt, rt, lx, ly, rx, ry)
        self._push()

    def _push(self):
        if not self.vpad:
            return
        lt, rt, lx, ly, rx, ry = getattr(self, "_state", (0, 0, 0, 0, 0, 0))
        xb = 0
        for gip_bit, xusb_bit in GIP_TO_XUSB:
            if self.buttons & gip_bit:
                xb |= xusb_bit
        if self.guide:
            xb |= XUSB["GUIDE"]
        state = (xb, min(lt >> 2, 255), min(rt >> 2, 255), lx, ly, rx, ry)
        if state != self.last_state:
            self.last_state = state
            self.vpad.update(*state)

    def _on_rumble_request(self, large, small):
        # called from the ViGEm notification thread
        left = large * RUMBLE_MAX // 255
        right = small * RUMBLE_MAX // 255
        log.debug("[%s] rumble request from game: large=%d small=%d", self.name, large, small)
        if (left, right) == getattr(self, "_last_rumble", None):
            return
        self._last_rumble = (left, right)
        self.post(lambda: self.client.send_rumble(rumble_packet(left, right)))

    def remove(self):
        if self.vpad:
            self.vpad.close()
            self.vpad = None
        log.info("[%s] gamepad removed", self.name)

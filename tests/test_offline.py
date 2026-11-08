"""Offline tests for xdongle (no hardware needed).  Run: python tests/test_offline.py"""

import hashlib
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from xdongle import auth as A
from xdongle import gip as G
from xdongle import mt76 as M
from xdongle.dongle import Dongle

failures = 0


def check(cond, msg):
    global failures
    if not cond:
        failures += 1
        print("FAIL:", msg)


# ----------------------------------------------------------------- GIP header coding
def test_headers():
    cases = [
        G.Header(0x05, 0x20, 1, 1),
        G.Header(0x20, 0x00, 7, 14),
        G.Header(0x06, 0x30 | 0x40 | 0x80, 3, 58, 274),      # first chunk of 274 bytes
        G.Header(0x06, 0x20 | 0x80, 3, 58, 58),              # odd actual length -> padded
        G.Header(0x06, 0x20 | 0x80, 3, 0, 274),              # completion chunk
        G.Header(0x04, 0x20, 2, 0),
        G.Header(0x04, 0x20, 2, 300),
    ]
    for h in cases:
        enc = G.encode_header(h)
        check(len(enc) % 2 == 0, f"odd header length {enc.hex()}")
        check(len(enc) == G.header_length(h), f"length mismatch {h}")
        d, n = G.decode_header(enc + b"\xaa" * 4)
        check(n == len(enc), f"decode length {h} {enc.hex()} -> {n}")
        check((d.command, d.options, d.sequence, d.packet_length) ==
              (h.command, h.options, h.sequence, h.packet_length), f"roundtrip {h} -> {d}")
        if h.options & G.OPT_CHUNK:
            check(d.chunk_offset == h.chunk_offset, f"chunk offset {h} -> {d}")
    # known packet: xone/xpad power-on
    check(G.encode_header(G.Header(0x05, 0x20, 1, 1)) + b"\0" == bytes.fromhex("0520010100"),
          "power-on packet bytes")


# ----------------------------------------------------------------- GIP chunking
class FakeAdapter(G.GipAdapter):
    def __init__(self):
        self.sent = []
        super().__init__("t", self.sent.append, lambda k: None, lambda c: None)


def parse_sent(buf):
    h, n = G.decode_header(buf)
    return h, buf[n:n + h.packet_length]


def test_chunking():
    adap = FakeAdapter()
    c = adap.get_client(0)
    payload = bytes(range(256)) * 2
    payload = payload[:200]
    c.send_pkt(G.Header(G.CMD_AUTHENTICATE, G.OPT_INTERNAL, 0, len(payload)), payload)
    h, d = parse_sent(adap.sent[-1])
    check(h.options & G.OPT_CHUNK_START and h.chunk_offset == 200 and d == payload[:58],
          f"first chunk {h}")
    # device acknowledges 58 bytes
    ack = struct.pack("<BBBH2xH", 0, G.CMD_AUTHENTICATE, 0x20, 58, 142)
    adap.process_buffer(G.encode_header(G.Header(1, 0x20, 9, 9)) + ack)
    got = b"".join(parse_sent(b)[1] for b in adap.sent[1:])
    check(got == payload[58:], f"remaining chunks {len(got)}")
    ack = struct.pack("<BBBH2xH", 0, G.CMD_AUTHENTICATE, 0x20, 200, 0)
    n_before = len(adap.sent)
    adap.process_buffer(G.encode_header(G.Header(1, 0x20, 9, 9)) + ack)
    h, d = parse_sent(adap.sent[-1])
    check(len(adap.sent) == n_before + 1 and h.packet_length == 0 and h.chunk_offset == 200,
          f"completion chunk {h}")
    check(c.chunk_buf_in is None, "outgoing buffer released")

    # incoming chunked packet (e.g. a certificate)
    got_auth = []
    c.driver = type("D", (), {"on_authenticate": lambda self, d: got_auth.append(d)})()
    blob = os.urandom(150)
    adap.sent.clear()
    pos = 0
    first = True
    while pos < len(blob):
        n = min(58, len(blob) - pos)
        if first:
            h = G.Header(6, 0x20 | 0x40 | 0x80 | 0x10, 5, n, len(blob))
        else:
            h = G.Header(6, 0x20 | 0x80, 5, n, pos)
        adap.process_buffer(G.encode_header(h) + blob[pos:pos + n])
        first = False
        pos += n
    adap.process_buffer(G.encode_header(G.Header(6, 0x20 | 0x80, 5, 0, len(blob))))
    check(got_auth == [blob], "incoming chunk reassembly")
    acks = [parse_sent(b) for b in adap.sent]
    check(acks and all(h.command == 1 for h, _ in acks), "chunk acknowledgements sent")


# ----------------------------------------------------------------- auth handshake
class FakeAuthDevice:
    """Minimal device side of the GIP auth handshake (v1 RSA or v2 ECDH)."""

    def __init__(self, version):
        self.version = version
        self.transcript = hashlib.sha256()
        self.random = os.urandom(32)
        self.out = []
        self.host_random = None
        self.master = None
        self.upgraded = version == 1
        if version == 1:
            self.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        else:
            self.ec = ec.generate_private_key(ec.SECP256R1())

    def _data(self, cmd, payload, hs_cmd=None):
        ver = 2 if cmd >= 0x21 else 1
        dh = struct.pack(">BBH", cmd, ver, len(payload))
        hs = struct.pack(">BBBBH", 0, 0xC0, 0, cmd if hs_cmd is None else hs_cmd,
                         len(dh) + len(payload))
        pkt = hs + dh + payload
        return pkt

    def _send(self, pkt, hashed=True):
        if hashed:
            self.transcript.update(pkt[6:])
        self.out.append(pkt)

    def ack(self):
        self.out.append(struct.pack(">BBBBH", 0, 0x01, 0, 0x01, 0))

    def receive(self, pkt, acknowledge):
        if pkt[0] == A.CTX_CONTROL:
            self.completed = True
            return
        ctx, opts, err, cmd, ln = struct.unpack(">BBBBH", pkt[:6])
        if opts & A.OPT_REQUEST:
            return self.on_request(cmd)
        # host data packet: hash dh+payload (exclude trailer)
        data_len = ln
        self.transcript.update(pkt[6:6 + data_len])
        payload = pkt[10:6 + data_len]
        if cmd == A.HOST_HELLO or cmd == A.AUTH2_HOST_HELLO:
            self.host_random = payload[:32]
        elif cmd == A.HOST_SECRET:
            pms = self.rsa.decrypt(payload[:256], padding.PKCS1v15())
            self.master = A.prf("Master Secret", pms, self.host_random + self.random, 48)
        elif cmd == A.AUTH2_HOST_PUBKEY:
            x = int.from_bytes(payload[:32], "big")
            y = int.from_bytes(payload[32:64], "big")
            peer = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
            secret = hashlib.sha256(self.ec.exchange(ec.ECDH(), peer)).digest()
            self.master = A.prf("Master Secret", secret, self.host_random + self.random, 48)
        elif cmd in (A.HOST_FINISH, A.AUTH2_HOST_FINISH):
            # verify host finished (transcript before this packet)
            self.host_finish_ok = True
        self.ack()

    def on_request(self, cmd):
        if cmd == A.CLIENT_HELLO and self.version == 2 and not self.upgraded:
            # signal v2: handshake command differs from data command
            self.upgraded = True
            self.transcript = hashlib.sha256()
            self.out.append(self._data(A.AUTH2_CLIENT_HELLO, bytes(172), hs_cmd=A.CLIENT_HELLO))
            return
        if cmd == A.CLIENT_HELLO:
            self._send(self._data(cmd, self.random + bytes(48)))
        elif cmd == A.CLIENT_CERTIFICATE:
            der = self.rsa.public_key().public_bytes(serialization.Encoding.DER,
                                                     serialization.PublicFormat.PKCS1)
            assert len(der) == 270, len(der)
            self._send(self._data(cmd, b"\x01\x02junk" + der + b"tail"))
        elif cmd == A.AUTH2_CLIENT_HELLO:
            self._send(self._data(cmd, self.random + bytes(140)))
        elif cmd == A.AUTH2_CLIENT_CERTIFICATE:
            cert = b"XCRT" + bytes(136) + b"NanoChip".ljust(32, b"\0") + b"rev1".ljust(20, b"\0")
            self._send(self._data(cmd, cert + bytes(576)))
        elif cmd == A.AUTH2_CLIENT_PUBKEY:
            n = self.ec.public_key().public_numbers()
            self._send(self._data(cmd, n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big") +
                                  bytes(64)))
        elif cmd in (A.CLIENT_FINISH, A.AUTH2_CLIENT_FINISH):
            t = self.transcript.copy().digest()
            fin = A.prf("Device Finished", self.master, t, 32)
            self._send(self._data(cmd, fin + bytes(32)))


def run_auth(version):
    keys = []
    dev = FakeAuthDevice(version)
    host = A.GipAuth(lambda p, ack: dev.receive(p, ack), keys.append, f"v{version}")
    host.start()
    for _ in range(50):
        if not dev.out:
            break
        pkt = dev.out.pop(0)
        host.process(pkt)
    check(host.completed and len(keys) == 1, f"auth v{version} did not complete")
    if keys:
        expect = A.prf("EXPORTER DAWN data channel session key for controller", dev.master,
                       dev.host_random + dev.random, 16)
        check(keys[0] == expect, f"auth v{version} session key mismatch")


# ----------------------------------------------------------------- dongle integration
class FakeUsb:
    def __init__(self):
        self.writes = []
        self.gone = False

    def control_in(self, req, value, index, length):
        return bytes(length)

    def control_out(self, req, value, index, data=b""):
        return len(data)

    def bulk_write(self, data, ep=0x04):
        self.writes.append(bytes(data))
        return len(data)


class FakeVpad:
    instances = []

    def __init__(self, on_rumble):
        self.on_rumble = on_rumble
        self.states = []
        self.closed = False
        FakeVpad.instances.append(self)

    def update(self, *state):
        self.states.append(state)

    def close(self):
        self.closed = True


CTRL = bytes.fromhex("7e3a1b2c3d4e")
DONGLE = bytes.fromhex("6245bd010203")


def rx_message(frame, wcid=0xFF, l2pad=False, hdr_len=24):
    if l2pad:
        frame = frame[:hdr_len] + b"\0\0" + frame[hdr_len:]
    mpdu = len(frame) - (2 if l2pad else 0)
    rxinfo = (1 << 14) if l2pad else 0
    rxwi = struct.pack("<IIHH4s16s", rxinfo, wcid | (mpdu << 16), 0, 0, b"", b"")
    body = rxwi + frame
    body += b"\0" * ((-len(body)) % 4)
    info = (M.MT_WLAN_PORT << 27) | len(body)
    return struct.pack("<I", info) + body + b"\0" * 4


def gip_from_write(w):
    """Extract a GIP buffer from a client data packet written by Dongle.send_client_packet."""
    body = w[4:]
    # data8 + txwi(20) + qos hdr(26) + pad(2)
    gipbuf = body[8 + 20 + 26 + 2:]
    tw_len = struct.unpack_from("<H", body, 8 + 6)[0]
    return gipbuf[:tw_len - 26]


def qos_frame(gipbuf):
    fc = 0x0088 | 0x0100      # QoS data, ToDS
    hdr = struct.pack("<HH", fc, 0) + DONGLE + CTRL + DONGLE + b"\0\0" + b"\0\0"
    return hdr + gipbuf


def test_dongle():
    usb = FakeUsb()
    d = Dongle(usb, b"", FakeVpad)
    d.mt.address = DONGLE
    d.mt.channel = d.mt.channels[0]
    d.ready = True

    # association request
    assoc = struct.pack("<HH", 0x0000, 0) + DONGLE + CTRL + DONGLE + b"\0\0" + bytes(10)
    d._process_message(rx_message(assoc))
    check(d.clients[0] is not None and d.clients[0].address == CTRL, "client associated")

    # announce (with L2 padding, wcid 1)
    ann = CTRL + b"\0\0" + struct.pack("<HH", 0x045E, 0x0B4C) + struct.pack("<4H", 6, 19, 50, 0) \
        + struct.pack("<4H", 12, 6, 0, 0)
    usb.writes.clear()
    gbuf = G.encode_header(G.Header(G.CMD_ANNOUNCE, 0x20, 1, len(ann))) + ann
    d._process_message(rx_message(qos_frame(gbuf), wcid=1, l2pad=True, hdr_len=26))
    sent = [G.decode_header(gip_from_write(w))[0] for w in usb.writes]
    check(any(h.command == G.CMD_IDENTIFY for h in sent), f"identify requested: {sent}")

    # identify response with gamepad class + one interface
    cls = b"Windows.Xbox.Input.Gamepad"
    body = bytearray(16)                        # offsets filled below (relative to body)
    blob = bytearray()

    def add(b):
        off = 16 + len(blob)
        blob.extend(b)
        return off
    fw_off = add(bytes([1]) + struct.pack("<HH", 1, 0))
    caps_out = add(bytes([1, 0]))
    caps_in = add(bytes([1, 0]))
    classes_off = add(bytes([1]) + struct.pack("<H", len(cls)) + cls)
    intf_off = add(bytes([1]) + bytes(16))
    body[:] = struct.pack("<8H", 0, fw_off, 0, caps_out, caps_in, classes_off, intf_off, 0)
    ident = bytes(16) + bytes(body) + bytes(blob)
    usb.writes.clear()
    gbuf = G.encode_header(G.Header(G.CMD_IDENTIFY, 0x20, 2, len(ident))) + ident
    if len(gbuf) - 4 > 58:
        # send as chunked like a real device would
        total = len(ident)
        pos = 0
        while pos < total:
            n = min(58, total - pos)
            opts = 0x20 | 0x80 | (0x40 | 0x10 if pos == 0 else 0)
            h = G.Header(G.CMD_IDENTIFY, opts, 2, n, total if pos == 0 else pos)
            d._process_message(rx_message(qos_frame(G.encode_header(h) + ident[pos:pos + n]),
                                          wcid=1))
            pos += n
        h = G.Header(G.CMD_IDENTIFY, 0x20 | 0x80, 2, 0, total)
        d._process_message(rx_message(qos_frame(G.encode_header(h)), wcid=1))
    client = d.clients[0].adapter.clients[0]
    check(client.classes == [cls.decode()], f"classes parsed: {client.classes}")
    time.sleep(0.8)
    d._run_timers()
    check(isinstance(client.driver, G.Gamepad), "gamepad driver probed")
    cmds = [G.decode_header(gip_from_write(w))[0].command for w in usb.writes]
    for c in (G.CMD_POWER, G.CMD_LED, G.CMD_AUTHENTICATE, G.CMD_RUMBLE):
        check(c in cmds, f"init command 0x{c:02x} sent ({[hex(x) for x in cmds]})")

    # input: A + dpad up, left trigger full, left stick
    inp = struct.pack("<HHHhhhh", (1 << 4) | (1 << 8), 1023, 0, -32768, 1000, 0, 32767)
    gbuf = G.encode_header(G.Header(G.CMD_INPUT, 0x00, 3, len(inp))) + inp
    d._process_message(rx_message(qos_frame(gbuf), wcid=1))
    vp = FakeVpad.instances[-1]
    check(vp.states and vp.states[-1] == (0x1000 | 0x0001, 255, 0, -32768, 1000, 0, 32767),
          f"vpad state {vp.states[-1:]}")
    # guide button
    gbuf = G.encode_header(G.Header(G.CMD_VIRTUAL_KEY, 0x20 | 0x10, 4, 2)) + bytes([1, 0x5B])
    d._process_message(rx_message(qos_frame(gbuf), wcid=1))
    check(vp.states[-1][0] & 0x0400, "guide pressed")
    # rumble request from game -> queued -> sent
    usb.writes.clear()
    vp.on_rumble(255, 128)
    kind, fn, _ = d.queue.get_nowait()
    fn()
    h, n = G.decode_header(gip_from_write(usb.writes[-1]))
    check(h.command == G.CMD_RUMBLE and gip_from_write(usb.writes[-1])[n + 4:n + 6] == bytes([100, 50]),
          "rumble packet")
    # controller turns off: status without connected bit
    st = bytes([0x00, 0, 0, 0])
    gbuf = G.encode_header(G.Header(G.CMD_STATUS, 0x20, 5, 4)) + st
    d._process_message(rx_message(qos_frame(gbuf), wcid=1))
    check(vp.closed, "virtual pad closed on disconnect")
    # disassociation
    dis = struct.pack("<HH", 0x00A0, 0) + DONGLE + CTRL + DONGLE + b"\0\0" + b"\x08\x00"
    d._process_message(rx_message(dis, wcid=1))
    check(d.clients[0] is None, "client removed")


if __name__ == "__main__":
    test_headers()
    test_chunking()
    run_auth(1)
    run_auth(2)
    test_dongle()
    print("all tests passed" if not failures else f"{failures} failure(s)")
    sys.exit(1 if failures else 0)

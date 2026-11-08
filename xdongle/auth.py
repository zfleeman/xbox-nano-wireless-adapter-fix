"""GIP authentication handshake (host side).

Port of xone's auth/auth.c + auth/crypto.c (GPL-2.0-or-later). Like xone, the client
certificate is NOT validated - we only need the handshake to complete so the controller
can derive the link encryption key. Supports the RSA (v1) and ECDH P-256 (v2) variants.
"""

import hashlib
import hmac
import logging
import os
import struct

from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

log = logging.getLogger("xdongle.auth")

TRAILER_LEN = 8
RANDOM_LEN = 32
CERTIFICATE_MAX_LEN = 1024
PUBKEY_LEN = 270
SECRET_LEN = 48
ENCRYPTED_PMS_LEN = 256
TRANSCRIPT_LEN = 32
SESSION_KEY_LEN = 16
AUTH2_PUBKEY_LEN = 64

CTX_HANDSHAKE = 0x00
CTX_CONTROL = 0x01
CTRL_COMPLETE = 0x00

OPT_ACKNOWLEDGE = 0x01
OPT_REQUEST = 0x02
OPT_FROM_HOST = 0x40

HOST_HELLO = 0x01
CLIENT_HELLO = 0x02
CLIENT_CERTIFICATE = 0x03
HOST_SECRET = 0x05
HOST_FINISH = 0x07
CLIENT_FINISH = 0x08
AUTH2_HOST_HELLO = 0x21
AUTH2_CLIENT_HELLO = 0x22
AUTH2_CLIENT_CERTIFICATE = 0x23
AUTH2_CLIENT_PUBKEY = 0x24
AUTH2_HOST_PUBKEY = 0x25
AUTH2_HOST_FINISH = 0x26
AUTH2_CLIENT_FINISH = 0x27

HANDSHAKE_HDR_LEN = 6   # context, options, error, command, be16 length
DATA_HDR_LEN = 4        # command, version, be16 length
FULL_HDR_LEN = HANDSHAKE_HDR_LEN + DATA_HDR_LEN

# payload sizes the host asks the client for
LEN_CLIENT_HELLO = 32 + 48
LEN_CLIENT_FINISH = 32 + 32
LEN_AUTH2_CLIENT_HELLO = 32 + 108 + 32
LEN_AUTH2_CLIENT_CERT = 4 + 136 + 32 + 20 + 576
LEN_AUTH2_CLIENT_PUBKEY = 64 + 64


def prf(label, key, seed, out_len):
    """TLS-style P_SHA256(key, label || seed)."""
    label = label.encode()
    a = hmac.new(key, label + seed, hashlib.sha256).digest()
    out = b""
    while len(out) < out_len:
        out += hmac.new(key, a + label + seed, hashlib.sha256).digest()
        a = hmac.new(key, a, hashlib.sha256).digest()
    return out[:out_len]


def _der_len(buf, pos):
    n = buf[pos]
    pos += 1
    if n < 0x80:
        return n, pos
    cnt = n & 0x7F
    return int.from_bytes(buf[pos:pos + cnt], "big"), pos + cnt


def parse_rsa_public_key(der):
    """Parse a PKCS#1 RSAPublicKey: SEQUENCE { INTEGER n, INTEGER e }."""
    if der[0] != 0x30:
        raise ValueError("not a SEQUENCE")
    _, pos = _der_len(der, 1)
    ints = []
    for _ in range(2):
        if der[pos] != 0x02:
            raise ValueError("expected INTEGER")
        ln, pos = _der_len(der, pos + 1)
        ints.append(int.from_bytes(der[pos:pos + ln], "big"))
        pos += ln
    return rsa.RSAPublicNumbers(ints[1], ints[0]).public_key()


class GipAuth:
    """Drives the handshake. `send(payload, acknowledge)` sends a GIP AUTHENTICATE packet;
    `on_key(key)` is called with the 16-byte session key once the handshake succeeds."""

    def __init__(self, send, on_key, name="client"):
        self.send = send
        self.on_key = on_key
        self.name = name
        self.transcript = hashlib.sha256()
        self.last_sent = None
        self.random_host = b""
        self.random_client = b""
        self.pubkey_client = b""
        self.pubkey_client2 = b""
        self.master_secret = b""
        self.completed = False
        self.failed = False

    # ---------------------------------------------------------------- sending
    def _send_pkt(self, cmd, payload):
        """payload = everything after the full header, excluding the trailer."""
        version = 0x02 if cmd >= AUTH2_HOST_HELLO else 0x01
        data_len = DATA_HDR_LEN + len(payload)
        hs = struct.pack(">BBBBH", CTX_HANDSHAKE, OPT_ACKNOWLEDGE | OPT_FROM_HOST, 0, cmd, data_len)
        dh = struct.pack(">BBH", cmd, version, data_len - DATA_HDR_LEN)
        self.last_sent = cmd
        self.transcript.update(dh + payload)
        self.send(hs + dh + payload + bytes(TRAILER_LEN), True)

    def _request_pkt(self, cmd, length):
        hs = struct.pack(">BBBBH", CTX_HANDSHAKE, OPT_REQUEST | OPT_FROM_HOST, 0, cmd,
                         length + DATA_HDR_LEN)
        self.send(hs + bytes(TRAILER_LEN), True)

    def start(self):
        self.random_host = os.urandom(RANDOM_LEN)
        log.debug("[%s] auth: host hello (v1)", self.name)
        self._send_pkt(HOST_HELLO, self.random_host + bytes(8))

    def _send_hello2(self):
        self.random_host = os.urandom(RANDOM_LEN)
        log.debug("[%s] auth: host hello (v2)", self.name)
        self._send_pkt(AUTH2_HOST_HELLO, self.random_host + bytes(4))

    def _send_finish(self, cmd):
        digest = self.transcript.copy().digest()
        self._send_pkt(cmd, prf("Host Finished", self.master_secret, digest, TRANSCRIPT_LEN))

    # ---------------------------------------------------------------- receiving
    def process(self, data):
        if len(data) < HANDSHAKE_HDR_LEN:
            raise ValueError("auth packet too short")
        options, error, command = data[1], data[2], data[3]   # data[0] is the context
        if error:
            self.failed = True
            raise RuntimeError(f"client reported auth error 0x{error:02x} (cmd 0x{command:02x})")
        if options & OPT_ACKNOWLEDGE:
            if command == 0x01:
                return self._handle_ack()
            self.failed = True
            raise RuntimeError(f"handshake failed: 0x{command:02x}")
        return self._process_data(data)

    def _handle_ack(self):
        cmd = self.last_sent
        if cmd == AUTH2_HOST_HELLO:
            self._request_pkt(AUTH2_CLIENT_HELLO, LEN_AUTH2_CLIENT_HELLO)
        elif cmd == AUTH2_HOST_PUBKEY:
            self._send_finish(AUTH2_HOST_FINISH)
        elif cmd == AUTH2_HOST_FINISH:
            self._request_pkt(AUTH2_CLIENT_FINISH, LEN_CLIENT_FINISH)
        elif cmd == HOST_HELLO:
            self._request_pkt(CLIENT_HELLO, LEN_CLIENT_HELLO)
        elif cmd == HOST_SECRET:
            self._send_finish(HOST_FINISH)
        elif cmd == HOST_FINISH:
            self._request_pkt(CLIENT_FINISH, LEN_CLIENT_FINISH)
        else:
            raise RuntimeError(f"unexpected auth ack after 0x{cmd}")

    def _process_data(self, data):
        if len(data) < FULL_HDR_LEN:
            raise ValueError("auth data packet too short")
        hs_cmd = data[3]
        d_cmd = data[HANDSHAKE_HDR_LEN]
        if hs_cmd != d_cmd:
            # client wants auth v2: reset transcript and restart
            log.debug("[%s] auth: protocol upgrade to v2", self.name)
            self.transcript = hashlib.sha256()
            self._send_hello2()
            return
        payload = data[FULL_HDR_LEN:]
        deferred = self._dispatch(d_cmd, payload)
        self.transcript.update(data[HANDSHAKE_HDR_LEN:])
        if deferred:
            deferred()

    def _dispatch(self, cmd, payload):
        if cmd == AUTH2_CLIENT_HELLO:
            if len(payload) < LEN_AUTH2_CLIENT_HELLO:
                raise ValueError("short client hello v2")
            self.random_client = payload[:RANDOM_LEN]
            self._request_pkt(AUTH2_CLIENT_CERTIFICATE, LEN_AUTH2_CLIENT_CERT)
        elif cmd == AUTH2_CLIENT_CERTIFICATE:
            if len(payload) < LEN_AUTH2_CLIENT_CERT:
                raise ValueError("short client certificate v2")
            chip = payload[140:172].split(b"\0")[0].decode(errors="replace")
            rev = payload[172:192].split(b"\0")[0].decode(errors="replace")
            log.info("[%s] auth v2 certificate: header=%r chip=%r revision=%r", self.name,
                     payload[:4], chip, rev)
            self._request_pkt(AUTH2_CLIENT_PUBKEY, LEN_AUTH2_CLIENT_PUBKEY)
        elif cmd == AUTH2_CLIENT_PUBKEY:
            if len(payload) < LEN_AUTH2_CLIENT_PUBKEY:
                raise ValueError("short client pubkey")
            self.pubkey_client2 = payload[:AUTH2_PUBKEY_LEN]
            return self._exchange_ecdh
        elif cmd in (CLIENT_FINISH, AUTH2_CLIENT_FINISH):
            return self._handle_finish(payload)
        elif cmd == CLIENT_HELLO:
            if len(payload) < LEN_CLIENT_HELLO:
                raise ValueError("short client hello")
            self.random_client = payload[:RANDOM_LEN]
            self._request_pkt(CLIENT_CERTIFICATE, CERTIFICATE_MAX_LEN)
        elif cmd == CLIENT_CERTIFICATE:
            if len(payload) > CERTIFICATE_MAX_LEN:
                raise ValueError("certificate too long")
            i = payload.find(b"\x30\x82\x01\x0a")
            if i < 0 or i + PUBKEY_LEN > len(payload):
                raise ValueError("no RSA key in certificate")
            self.pubkey_client = payload[i:i + PUBKEY_LEN]
            return self._exchange_rsa
        else:
            raise RuntimeError(f"unknown auth command 0x{cmd:02x}")
        return None

    def _exchange_rsa(self):
        rand = self.random_host + self.random_client
        pms = os.urandom(SECRET_LEN)
        key = parse_rsa_public_key(self.pubkey_client)
        enc = key.encrypt(pms, padding.PKCS1v15())
        self.master_secret = prf("Master Secret", pms, rand, SECRET_LEN)
        log.debug("[%s] auth: sending host secret (RSA)", self.name)
        self._send_pkt(HOST_SECRET, enc)

    def _exchange_ecdh(self):
        rand = self.random_host + self.random_client
        x = int.from_bytes(self.pubkey_client2[:32], "big")
        y = int.from_bytes(self.pubkey_client2[32:64], "big")
        peer = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        priv = ec.generate_private_key(ec.SECP256R1())
        nums = priv.public_key().public_numbers()
        own = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
        shared = priv.exchange(ec.ECDH(), peer)
        secret = hashlib.sha256(shared).digest()
        self.master_secret = prf("Master Secret", secret, rand, SECRET_LEN)
        log.debug("[%s] auth: sending host pubkey (ECDH)", self.name)
        self._send_pkt(AUTH2_HOST_PUBKEY, own)

    def _handle_finish(self, payload):
        if len(payload) < LEN_CLIENT_FINISH:
            raise ValueError("short client finish")
        digest = self.transcript.copy().digest()
        expected = prf("Device Finished", self.master_secret, digest, TRANSCRIPT_LEN)
        if payload[:TRANSCRIPT_LEN] != expected:
            self.failed = True
            raise RuntimeError("auth transcript mismatch")
        return self._complete

    def _complete(self):
        rand = self.random_host + self.random_client
        key = prf("EXPORTER DAWN data channel session key for controller", self.master_secret,
                  rand, SESSION_KEY_LEN)
        # control packet: handshake complete (not acknowledged)
        self.send(bytes([CTX_CONTROL, CTRL_COMPLETE]), False)
        self.completed = True
        log.info("[%s] authentication complete", self.name)
        self.on_key(key)

r"""Measure how long xdongle's software path adds to one controller input report.

Feeds synthetic GIP input reports through the real code: USB-callback hand-off -> worker queue ->
MT76/802.11/GIP parsing -> Gamepad mapping -> ViGEmBus update (a real virtual Xbox 360 pad).

Run: .venv\Scripts\python.exe tests\latency_bench.py   (about 30 s; briefly plugs in virtual
Xbox 360 pads and runs every CPU thread at 100% for the load tests). Needs no dongle.
"""
import ctypes
import logging
import os
import struct
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
logging.basicConfig(level=logging.WARNING)

import test_offline as T

from xdongle import gip as G
from xdongle.dongle import Dongle
from xdongle.vpad import VirtualPad

N = 2000
INTERVAL = 0.004          # one report every 4 ms
pc = time.perf_counter_ns


def stats(name, xs_ns):
    xs = sorted(x / 1000 for x in xs_ns)
    p = lambda q: xs[min(len(xs) - 1, int(q * len(xs)))]
    print(f"  {name:44s} median {p(0.5):7.1f} us   p99 {p(0.99):7.1f} us   "
          f"max {xs[-1]:8.1f} us", flush=True)


def make_dongle(factory):
    usb = T.FakeUsb()
    d = Dongle(usb, b"", factory)
    d.mt.address = T.DONGLE
    d.mt.channel = d.mt.channels[0]
    d.ready = True
    assoc = struct.pack("<HH", 0, 0) + T.DONGLE + T.CTRL + T.DONGLE + b"\0\0" + bytes(10)
    d._process_message(T.rx_message(assoc))
    ann = T.CTRL + b"\0\0" + struct.pack("<HH", 0x045E, 0x0B4C) + struct.pack("<4H", 6, 19, 50, 0) \
        + struct.pack("<4H", 12, 6, 0, 0)
    d._process_message(T.rx_message(T.qos_frame(
        G.encode_header(G.Header(G.CMD_ANNOUNCE, 0x20, 1, len(ann))) + ann), wcid=1, l2pad=True,
        hdr_len=26))
    cls = b"Windows.Xbox.Input.Gamepad"
    blob = bytearray()

    def add(b):
        off = 16 + len(blob)
        blob.extend(b)
        return off
    fw = add(bytes([1]) + struct.pack("<HH", 1, 0))
    co = add(bytes([1, 0]))
    ci = add(bytes([1, 0]))
    cl = add(bytes([1]) + struct.pack("<H", len(cls)) + cls)
    it = add(bytes([1]) + bytes(16))
    ident = bytes(16) + struct.pack("<8H", 0, fw, 0, co, ci, cl, it, 0) + bytes(blob)
    total, pos = len(ident), 0
    while pos < total:
        n = min(58, total - pos)
        opts = 0x20 | 0x80 | (0x50 if pos == 0 else 0)
        h = G.Header(G.CMD_IDENTIFY, opts, 2, n, total if pos == 0 else pos)
        d._process_message(T.rx_message(T.qos_frame(G.encode_header(h) + ident[pos:pos + n]), wcid=1))
        pos += n
    d._process_message(T.rx_message(T.qos_frame(
        G.encode_header(G.Header(G.CMD_IDENTIFY, 0xA0, 2, 0, total))), wcid=1))
    time.sleep(0.8)
    d._run_timers()
    assert isinstance(d.clients[0].adapter.clients[0].driver, G.Gamepad)
    return d


def input_msgs(n):
    out = []
    for i in range(n):
        inp = struct.pack("<HHHhhhh", 0, 0, 0, (i % 2000) - 1000, 0, 0, 0)  # stick moves every report
        gbuf = G.encode_header(G.Header(G.CMD_INPUT, 0x00, i % 255 + 1, len(inp))) + inp
        out.append(T.rx_message(T.qos_frame(gbuf), wcid=1))
    return out


class TimedPad(VirtualPad):
    done = []

    def update(self, *a):
        super().update(*a)
        TimedPad.done.append(pc())


def end_to_end(label):
    """USB callback hand-off -> worker thread -> parse -> ViGEm, at a realistic report rate."""
    TimedPad.done = []
    d = make_dongle(TimedPad)
    msgs = input_msgs(N)
    th = threading.Thread(target=d.run, daemon=True)
    th.start()
    puts = []
    for m in msgs:
        puts.append(pc())
        d._on_usb_buffer(0x84, m)          # exactly what the libusb completion callback does
        time.sleep(INTERVAL)
    time.sleep(0.2)
    d.stopping = True
    th.join(1)
    d.clients[0].adapter.clients[0].driver.remove()
    assert len(TimedPad.done) == N, len(TimedPad.done)
    stats(label, [b - a for a, b in zip(puts, TimedPad.done)])


def main():
    print(f"{N} reports, one every {INTERVAL * 1000:.0f} ms\n")
    print("Pieces (idle CPU):")
    T.FakeVpad.instances.clear()
    d = make_dongle(T.FakeVpad)
    msgs = input_msgs(N)
    xs = []
    for m in msgs:
        t = pc()
        d._process_message(m)
        xs.append(pc() - t)
    assert len(T.FakeVpad.instances[-1].states) >= N
    stats("parse + map (radio/802.11/GIP -> pad state)", xs)

    vp = VirtualPad(lambda a, b: None)
    xs = []
    for i in range(N):
        t = pc()
        vp.update(0, 0, 0, (i % 2000) - 1000, 0, 0, 0)
        xs.append(pc() - t)
        time.sleep(INTERVAL / 4)
    vp.close()
    stats("ViGEmBus update (virtual pad call)", xs)

    print("\nWhole software path, report arrives -> Windows sees new pad state:")
    end_to_end("idle CPU")

    busy = [subprocess.Popen([sys.executable, "-c", "while True: pass"])
            for _ in range(os.cpu_count())]
    try:
        time.sleep(1)
        end_to_end(f"all {os.cpu_count()} CPU threads at 100% (normal priority)")
        k32 = ctypes.windll.kernel32
        k32.GetCurrentProcess.restype = ctypes.c_void_p
        k32.SetPriorityClass(ctypes.c_void_p(k32.GetCurrentProcess()), 0x8000)  # ABOVE_NORMAL
        end_to_end("100% CPU, xdongle at above-normal priority")
    finally:
        for p in busy:
            p.kill()


if __name__ == "__main__":
    main()

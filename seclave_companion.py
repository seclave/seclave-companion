#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 Seclave AB
"""Seclave Companion - a desktop table view for a Seclave 2.0 hardware password
manager, over its USB-slave (CDC-ACM serial) protocol.

One self-contained program, Python standard library only: no pip installs, no
sockets, no IPC. Connect the device, put it in its "Usb slave" menu, and this
app enumerates the entries into a searchable, sortable table and lets you copy a
username or password, or add/edit/delete an entry - each secret action honoring
the device's on-screen confirmation.

Read this file top to bottom; each section depends only on the ones above it:

    constants / style tokens
    SecretBuffer          - zeroizable landing zone for secret bytes
    protocol codec        - integer/field encoding, response parsing
    serial transport      - PosixSerial (termios), WindowsSerial (ctypes), find_port
    DeviceSession         - one method per protocol command
    Worker                - the single serial thread + a queue to the UI
    theming + UI          - ttk table, dialogs, "look at your Seclave" state
    main()

The real security boundary is the Seclave's own display-and-joystick trusted
path, not this process. This app is a convenience front-end.
"""

import io
import os
import sys
import glob
import time
import queue
import mmap
import struct
import string
import secrets
import argparse
import tempfile
import threading

# The only place a release version is written by hand. Everything else derives
# from it: the PyPI metadata, the deb/rpm, the Windows version resource, the
# installer, and the artifact names. See "Releasing" in README.md.
VERSION = "1.1.2"

# ---------------------------------------------------------------------------
# Optional tracing (--debug). Port discovery and the serial open are the two
# steps with nothing on screen to show for them, so they are what gets traced.
# A windowed build has no stderr, so the log then goes to a file the user can
# find; the path is printed once at startup when a console does exist.
# ---------------------------------------------------------------------------

DEBUG_LOG = "seclave_companion.log"

_debug_streams = []


def enable_debug():
    """Log to a file always, and to stderr when there is a real one. A windowed
    build has a stderr object that discards everything, so the file is what the
    user can actually read afterwards."""
    path = os.path.join(tempfile.gettempdir(), DEBUG_LOG)
    try:
        _debug_streams.append(open(path, "a", buffering=1))
    except OSError:
        pass
    if sys.stderr is not None and hasattr(sys.stderr, "write"):
        _debug_streams.append(sys.stderr)
    debug("Seclave Companion %s starting on %s, logging to %s",
          VERSION, sys.platform, path)


def debug(fmt, *args):
    if not _debug_streams:
        return
    line = "[%s] %s\n" % (time.strftime("%H:%M:%S"), fmt % args)
    for stream in _debug_streams:
        try:
            stream.write(line)
        except (OSError, ValueError):
            pass


# ---------------------------------------------------------------------------
# Protocol constants for the Seclave USB-slave (CDC-ACM serial) interface.
# ---------------------------------------------------------------------------

USB_VID = 0x20A0
USB_PID = 0x41E3

# Opcodes (first payload byte).
OP_GET_GROUP = 1
OP_GET_USERNAME = 2
OP_GET_PASSWORD = 3
OP_GET_OPTIONAL = 4
OP_GET_WWWFILL = 5
OP_GET_LABELIDX = 6
OP_GET_WWWFILLIDX = 7
OP_PUT_WWWFILL = 8
OP_PUT_ENTRY = 9
OP_DEL_ENTRY = 10
OP_DEL_WWWFILL = 11
OP_GET_BACKUP = 12

# Response status codes.
ST_OK = 0
ST_ENTRY_NOT_FOUND = 1
ST_PARSE_ERROR = 2          # never seen on the wire - the port vanishes instead
ST_ABORT = 3                # user declined on the device
ST_OUT_OF_INDEX = 4         # enumeration terminator, not an error
ST_LABEL_EXISTS = 5
ST_NO_SPACE = 6
ST_BAD_LABEL = 7
ST_BAD_DOMAIN = 8
ST_MORE_LABELS = 9          # GET_WWWFILL: success, and more logins for this domain

STATUS_MESSAGE = {
    ST_ENTRY_NOT_FOUND: "The entry was not found on the device.",
    ST_LABEL_EXISTS: "An entry with that label already exists.",
    ST_NO_SPACE: "The device is full (500 entries).",
    ST_BAD_LABEL: "The label or group has invalid characters or length.",
    ST_BAD_DOMAIN: "The domain has invalid characters or length.",
}

# Field maxima (bytes on the wire, Latin-1).
MAX_LABEL = 16
MAX_GROUP = 8
MAX_USERNAME = 50
MAX_PASSWORD = 50
MAX_OPTIONAL = 83
MAX_ENTRIES = 500

# Outer frame payload bound. A 0-length or >228 frame silently drops the device
# out of slave mode, so we never send one - a violation is a client bug.
MAX_FRAME_PAYLOAD = 228

# Size of the mmap arena each transport reads responses into. Device responses
# are small - the largest single field is a 224-byte backup blob - so 4 KiB is
# generous headroom for a whole response.
RECV_ARENA = 4096

# How long a single Windows ReadFile waits before reporting "nothing yet". The
# recv loop repeats it, so this only sets how fast Stop waiting takes effect.
RECV_POLL_MS = 250

WWWFILL_GROUP = "wwwfill"

# Charset the device accepts for label / group / domain (case-insensitive).
LABEL_CHARSET = set(string.ascii_letters + string.digits + "._-" +
                    "æÆåÅäÄöÖøØüÜß")

# Refuse to send a wwwfill write that would duplicate an existing
# (domain, username) pair - domain compared case-insensitively, username
# case-sensitively, matching the device's own uniqueness rule.
#
# Seclave firmware 2.6 and earlier can miss its own duplicate check, store the
# second copy, and later stop responding when such a pair is edited on the
# device. Every device in the field today runs an affected firmware, so this
# safeguard defaults ON. Relax it (set False) only for a device confirmed to
# run a firmware release later than 2.6, where the device refuses duplicates
# correctly and this client-side check becomes redundant and over-strict. The
# protocol exposes no firmware version today, so there is nothing to detect
# automatically.
ENFORCE_WWWFILL_DEDUP = True

CLIPBOARD_CLEAR_MS = 30_000  # auto-clear a copied secret after 30 s

# Preferred initial window size in pixels (width, height). The window opens at
# this size, or larger if the widgets need more room; the user can resize it.
WINDOW_SIZE = (1024, 1200)

# Color palette. Blue is the primary color; green is reserved for the single
# call-to-action button.
STYLE = {
    "blue": "#00749c",
    "blue_hover": "#00404c",
    "focus": "#00407a",
    "green": "#05bf85",
    "red": "#b3261e",
    "bg": "#ffffff",
    "body": "#384743",
    "heading": "#242e2b",
    "muted": "#a8adac",
    "white": "#ffffff",
}
MONO_FAMILIES = ["Menlo", "DejaVu Sans Mono", "Consolas", "Courier New"]


# ---------------------------------------------------------------------------
# SecretBuffer - a mutable, zeroizable home for a secret read off the wire.
# ---------------------------------------------------------------------------

class SecretBuffer:
    """Holds one secret's bytes in an anonymous mmap so we can overwrite them
    with zeros the instant we're done.

    A secret is read off the serial port straight into the transport's mmap arena
    (never into an intermediate `bytes`), then copied here mmap-to-mmap so it can
    outlive the arena, which is wiped after each command. Both live only in mmap
    pages we explicitly zero. The two copies we cannot control are the kernel's
    tty receive buffer, and the transient `str` created at the moment we display
    the value or place it on the clipboard (which the windowing/clipboard system
    may then retain). We do not lock pages into RAM: the real security boundary is
    the user confirming each read on the device, not host memory hygiene.

    `source` is any bytes-like object - typically a memoryview slice of the arena,
    which copies no intermediate bytes.
    """

    def __init__(self, source):
        self._length = len(source)
        # mmap needs at least one byte; an empty secret still gets a real map.
        self._map = mmap.mmap(-1, max(self._length, 1))
        if self._length:
            self._map[:self._length] = source

    def text(self):
        return bytes(self._map[:self._length]).decode("latin-1")

    def clear(self):
        self._map[:] = b"\x00" * len(self._map)

    def __len__(self):
        return self._length


# ---------------------------------------------------------------------------
# Protocol codec. Integers and length-prefixed fields share one variable-length
# encoding. Commands the host sends are wrapped in a 2-byte little-endian length
# prefix; responses from the device are NOT length-framed, so we parse them
# incrementally against the field count the in-flight command expects.
# ---------------------------------------------------------------------------

class NeedMore(Exception):
    """Not enough bytes accumulated yet to finish parsing a response."""


def encode_int(value):
    if value < 254:
        return bytes([value])
    nbytes = 1 if value <= 0xFF else 2
    return bytes([0xFF, nbytes]) + value.to_bytes(nbytes, "little")


def encode_field(data):
    return encode_int(len(data)) + data


def decode_int(buf, off):
    if off >= len(buf):
        raise NeedMore
    first = buf[off]
    if first != 0xFF:
        return first, off + 1
    if off + 1 >= len(buf):
        raise NeedMore
    nbytes = buf[off + 1]
    if nbytes not in (1, 2):
        raise ValueError("bad integer escape length %d" % nbytes)
    end = off + 2 + nbytes
    if end > len(buf):
        raise NeedMore
    return int.from_bytes(buf[off + 2:end], "little"), end


def decode_field_span(buf, off):
    """Return ((start, end), next_off) for a length-prefixed field, without
    copying - the caller decides whether to make a str or a SecretBuffer."""
    length, off = decode_int(buf, off)
    end = off + length
    if end > len(buf):
        raise NeedMore
    return (off, end), end


def build_frame(payload):
    if not (1 <= len(payload) <= MAX_FRAME_PAYLOAD):
        raise ValueError("frame payload out of range: %d bytes" % len(payload))
    return struct.pack("<H", len(payload)) + payload


def parse_response(buf, field_count):
    """Try to parse a complete response from `buf`.

    Returns (status, [spans]) once enough bytes are present, or None if more are
    still needed. A status other than OK / MORE_LABELS carries no fields.
    """
    try:
        status, off = decode_int(buf, 0)
        if status not in (ST_OK, ST_MORE_LABELS):
            return status, []
        spans = []
        for _ in range(field_count):
            span, off = decode_field_span(buf, off)
            spans.append(span)
        return status, spans
    except NeedMore:
        return None


def latin1(text):
    return text.encode("latin-1")


# ---------------------------------------------------------------------------
# Serial transport. CDC-ACM is a virtual UART, so configuration reduces to "raw
# mode" - baud is irrelevant. Each transport owns an mmap arena and reads one
# response at a time straight into it (never into an intermediate `bytes`). The
# shared interface is:
#   open(), write(bytes), begin_recv(), recv() -> memoryview, wipe(), wake(),
#   close().
# recv() blocks until at least one byte arrives (the device sends nothing while
# awaiting confirmation) and returns a memoryview of everything received so far;
# the session re-parses that view until the response is complete. wake()
# interrupts a blocked recv() for cancel / shutdown; wipe() zeros the used region
# after each command.
# ---------------------------------------------------------------------------

class Disconnected(Exception):
    """The port went away (user left the menu, unplug, or a framing fault)."""


class Cancelled(Exception):
    """A blocked read was interrupted on purpose (Stop waiting)."""


class _Arena:
    """A fixed anonymous mmap that one device response is read into.

    Bytes land directly in these pages, are parsed in place, and the used region
    is zeroed after every command (or the whole arena on close). This is what
    makes secret bytes wipeable end to end: they never sit in a Python `bytes`
    between the kernel and a SecretBuffer.
    """

    def __init__(self, size):
        self._map = mmap.mmap(-1, size)
        self.fill = 0

    def reset(self):
        self.fill = 0

    def view(self):
        return memoryview(self._map)[:self.fill]

    def tail(self):
        return memoryview(self._map)[self.fill:]

    def advance(self, count):
        self.fill += count

    def is_full(self):
        return self.fill >= len(self._map)

    def wipe(self):
        self._map[:self.fill] = b"\x00" * self.fill
        self.fill = 0

    def wipe_all(self):
        self._map[:] = b"\x00" * len(self._map)
        self.fill = 0

    def snapshot(self):
        return bytes(self._map)   # plain copy of the whole arena, for tests


class PosixSerial:
    def __init__(self, path):
        self.path = path
        self.fd = None
        self._reader = None
        self._wake_r, self._wake_w = os.pipe()
        self.arena = _Arena(RECV_ARENA)

    def open(self):
        import termios
        self.fd = os.open(self.path, os.O_RDWR | os.O_NOCTTY)
        iflag, oflag, cflag, lflag, ispeed, ospeed, cc = termios.tcgetattr(self.fd)
        lflag &= ~(termios.ECHO | termios.ICANON | termios.IEXTEN | termios.ISIG)
        iflag &= ~(termios.BRKINT | termios.ICRNL | termios.INPCK |
                   termios.ISTRIP | termios.IXON)
        oflag &= ~termios.OPOST
        cflag &= ~(termios.CSIZE | termios.PARENB)
        cflag |= termios.CS8
        cc = list(cc)
        cc[termios.VMIN] = 1
        cc[termios.VTIME] = 0
        termios.tcsetattr(self.fd, termios.TCSAFLUSH,
                          [iflag, oflag, cflag, lflag, ispeed, ospeed, cc])
        # readinto() lands bytes directly in the arena; closefd=False keeps the
        # fd ours to close explicitly.
        self._reader = io.FileIO(self.fd, mode="r", closefd=False)
        debug("opened %s", self.path)

    def write(self, data):
        import select
        import termios
        # A command starts here. Drop a "Stop waiting" that arrived after the
        # previous command finished (it would cancel this one spuriously), and
        # flush input, where the late response to a cancelled command would
        # otherwise be parsed as this command's reply (responses are unframed).
        readable, _, _ = select.select([self._wake_r], [], [], 0)
        if readable:
            os.read(self._wake_r, 4096)
        try:
            termios.tcflush(self.fd, termios.TCIFLUSH)
        except termios.error:
            raise Disconnected
        sent = 0
        while sent < len(data):
            try:
                sent += os.write(self.fd, data[sent:])
            except OSError:
                raise Disconnected

    def begin_recv(self):
        self.arena.reset()

    def recv(self):
        import select
        readable, _, _ = select.select([self.fd, self._wake_r], [], [])
        if self._wake_r in readable:
            os.read(self._wake_r, 4096)
            raise Cancelled
        if self.arena.is_full():
            # A well-formed response parses long before this; a full arena means
            # the stream is unframeable, so treat it as a lost connection.
            raise Disconnected
        try:
            count = self._reader.readinto(self.arena.tail())
        except OSError:
            raise Disconnected
        if not count:
            raise Disconnected
        self.arena.advance(count)
        return self.arena.view()

    def wipe(self):
        self.arena.wipe()

    def wake(self):
        os.write(self._wake_w, b"x")

    def close(self):
        self.arena.wipe_all()
        if self._reader is not None:
            self._reader.close()   # closefd=False, so the fd stays open here
            self._reader = None
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None


class WindowsSerial:
    """Win32 comm port via ctypes. Short read timeouts polled in a loop give the
    infinite blocking read that on-device confirmations require."""

    def __init__(self, path):
        # "\\.\COMx" reaches ports numbered above COM9.
        self.path = path if path.startswith("\\\\.\\") else "\\\\.\\" + path
        self.handle = None
        self.cancelled = False
        self.arena = _Arena(RECV_ARENA)

    def open(self):
        import ctypes
        from ctypes import wintypes
        # use_last_error makes ctypes capture GetLastError at the call site;
        # ctypes.get_last_error() then reads that capture. Asking Windows
        # directly later can return a code some intervening call overwrote.
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        # Explicit signatures are required, not cosmetic: ctypes marshals an
        # untyped Python int as a C int, and the access mask below (0xC0000000)
        # does not fit one. A HANDLE is pointer-sized, so it needs declaring
        # too or the value is truncated on 64-bit.
        k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                    wintypes.DWORD, wintypes.LPVOID,
                                    wintypes.DWORD, wintypes.DWORD,
                                    wintypes.HANDLE]
        k32.CreateFileW.restype = wintypes.HANDLE
        k32.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID,
                                 wintypes.DWORD, wintypes.LPDWORD,
                                 wintypes.LPVOID]
        k32.WriteFile.argtypes = [wintypes.HANDLE, wintypes.LPCVOID,
                                  wintypes.DWORD, wintypes.LPDWORD,
                                  wintypes.LPVOID]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.CancelIoEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
        k32.GetCommState.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
        k32.SetCommState.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
        k32.SetCommTimeouts.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
        k32.EscapeCommFunction.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        k32.ClearCommError.argtypes = [wintypes.HANDLE, wintypes.LPDWORD,
                                       wintypes.LPVOID]
        k32.PurgeComm.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        GENERIC = 0xC0000000            # GENERIC_READ | GENERIC_WRITE
        OPEN_EXISTING = 3
        INVALID_HANDLE = ctypes.c_void_p(-1).value
        self.handle = k32.CreateFileW(self.path, GENERIC, 0, None,
                                      OPEN_EXISTING, 0, None)
        if not self.handle or self.handle == INVALID_HANDLE:
            err = ctypes.get_last_error()
            self.handle = None
            debug("CreateFileW %s failed, error %d", self.path, err)
            raise Disconnected
        debug("opened %s", self.path)
        self._k32 = k32
        # A valid-but-cosmetic DCB; the device ignores line coding.
        class DCB(ctypes.Structure):
            _fields_ = [("DCBlength", wintypes.DWORD), ("BaudRate", wintypes.DWORD),
                        ("fFlags", wintypes.DWORD), ("wReserved", wintypes.WORD),
                        ("XonLim", wintypes.WORD), ("XoffLim", wintypes.WORD),
                        ("ByteSize", ctypes.c_byte), ("Parity", ctypes.c_byte),
                        ("StopBits", ctypes.c_byte), ("XonChar", ctypes.c_char),
                        ("XoffChar", ctypes.c_char), ("ErrorChar", ctypes.c_char),
                        ("EofChar", ctypes.c_char), ("EvtChar", ctypes.c_char),
                        ("wReserved1", wintypes.WORD)]
        dcb = DCB()
        dcb.DCBlength = ctypes.sizeof(DCB)
        if not k32.GetCommState(self.handle, ctypes.byref(dcb)):
            debug("GetCommState failed, error %d", ctypes.get_last_error())
        dcb.BaudRate = 115200
        dcb.ByteSize = 8
        dcb.Parity = 0
        dcb.StopBits = 0
        # fBinary | fDtrControl=ENABLE | fRtsControl=ENABLE. A CDC device that
        # waits for the host to raise DTR never sees our first frame otherwise.
        dcb.fFlags = 0x1 | 0x10 | 0x1000
        if not k32.SetCommState(self.handle, ctypes.byref(dcb)):
            debug("SetCommState failed, error %d", ctypes.get_last_error())

        class COMMTIMEOUTS(ctypes.Structure):
            _fields_ = [("ReadIntervalTimeout", wintypes.DWORD),
                        ("ReadTotalTimeoutMultiplier", wintypes.DWORD),
                        ("ReadTotalTimeoutConstant", wintypes.DWORD),
                        ("WriteTotalTimeoutMultiplier", wintypes.DWORD),
                        ("WriteTotalTimeoutConstant", wintypes.DWORD)]
        # MAXDWORD/MAXDWORD/RECV_POLL_MS is the documented way to say "return as
        # soon as any byte is here, else give up after RECV_POLL_MS". An all-zero
        # struct means the opposite on Windows: ReadFile waits for every byte
        # asked for, which never happens when a response is shorter than the
        # buffer. recv() loops over the short waits to get the infinite block.
        timeouts = COMMTIMEOUTS()
        timeouts.ReadIntervalTimeout = 0xFFFFFFFF
        timeouts.ReadTotalTimeoutMultiplier = 0xFFFFFFFF
        timeouts.ReadTotalTimeoutConstant = RECV_POLL_MS
        if not k32.SetCommTimeouts(self.handle, ctypes.byref(timeouts)):
            debug("SetCommTimeouts failed, error %d", ctypes.get_last_error())
        # DTR/RTS again through the escape codes: some drivers honour these when
        # they ignore the DCB flags.
        k32.EscapeCommFunction(self.handle, 5)   # SETDTR
        k32.EscapeCommFunction(self.handle, 3)   # SETRTS

    def write(self, data):
        import ctypes
        from ctypes import wintypes
        # A command starts here. Drop a "Stop waiting" that arrived after the
        # previous command finished (it would cancel this one spuriously), and
        # purge input, where the late response to a cancelled command would
        # otherwise be parsed as this command's reply (responses are unframed).
        self.cancelled = False
        self._k32.PurgeComm(self.handle, 0x0008)   # PURGE_RXCLEAR
        written = wintypes.DWORD(0)
        ok = self._k32.WriteFile(self.handle, data, len(data),
                                 ctypes.byref(written), None)
        # Opcode only: the rest of a put frame is the secret itself.
        debug("write %d bytes (opcode %s), ok=%s wrote=%d error=%d", len(data),
              data[2] if len(data) > 2 else "?", bool(ok), written.value,
              0 if ok else ctypes.get_last_error())
        if not ok:
            # wake()'s CancelIoEx aborts any I/O on the handle, this write
            # included; that is a cancel, not a dead port.
            raise Cancelled if self.cancelled else Disconnected

    def begin_recv(self):
        # The cancel flag is NOT cleared here: write() clears it when the
        # command starts, so a "Stop waiting" landing between write() and this
        # call still cancels the command instead of being lost.
        self.arena.reset()

    def recv(self):
        import ctypes
        from ctypes import wintypes
        if self.arena.is_full():
            raise Disconnected   # see PosixSerial.recv
        remaining = len(self.arena._map) - self.arena.fill
        # ReadFile writes straight into the arena pages at the current offset -
        # no intermediate ctypes/bytes buffer.
        dest = (ctypes.c_char * remaining).from_buffer(self.arena._map,
                                                       self.arena.fill)
        read = wintypes.DWORD(0)
        debug("read: waiting for up to %d bytes", remaining)
        while True:
            ok = self._k32.ReadFile(self.handle, dest, remaining,
                                    ctypes.byref(read), None)
            if not ok:
                err = ctypes.get_last_error()
                debug("read failed, error %d", err)
                raise Cancelled if self.cancelled else Disconnected
            if read.value:
                debug("read got %d bytes", read.value)
                self.arena.advance(read.value)
                return self.arena.view()
            if self.cancelled:
                raise Cancelled
            # Nothing yet - normally the device waiting for the user to
            # confirm. Probe that the port still exists: a surprise removal
            # can make ReadFile report success with zero bytes, which is
            # otherwise indistinguishable from a quiet device.
            errors = wintypes.DWORD(0)
            if not self._k32.ClearCommError(self.handle, ctypes.byref(errors),
                                            None):
                debug("port gone (ClearCommError error %d)",
                      ctypes.get_last_error())
                raise Disconnected

    def wipe(self):
        self.arena.wipe()

    def wake(self):
        # The recv loop notices the flag between polls; CancelIoEx cuts short a
        # read that is already blocked.
        self.cancelled = True
        if self.handle is not None:
            self._k32.CancelIoEx(self.handle, None)

    def close(self):
        self.arena.wipe_all()
        if self.handle is not None:
            self._k32.CloseHandle(self.handle)
            self.handle = None


def open_serial(path):
    if os.name == "nt":
        return WindowsSerial(path)
    return PosixSerial(path)


def _read_text(path):
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _linux_matches_seclave(tty_name):
    device = os.path.realpath("/sys/class/tty/%s/device" % tty_name)
    for _ in range(6):  # walk up to the USB device dir holding idVendor/idProduct
        vid = os.path.join(device, "idVendor")
        pid = os.path.join(device, "idProduct")
        if os.path.exists(vid) and os.path.exists(pid):
            return (_read_text(vid).lower() == "%04x" % USB_VID and
                    _read_text(pid).lower() == "%04x" % USB_PID)
        device = os.path.dirname(device)
    return False


def find_port(forced=None):
    """Return the device's serial node, or None if it isn't present."""
    if forced:
        return forced if os.path.exists(forced) or os.name == "nt" else None
    if sys.platform.startswith("linux"):
        if os.path.exists("/dev/seclave"):   # stable name if a udev rule provides one
            return "/dev/seclave"
        for node in sorted(glob.glob("/dev/ttyACM*")):
            if _linux_matches_seclave(os.path.basename(node)):
                return node
        return None
    if sys.platform == "darwin":
        matches = sorted(glob.glob("/dev/cu.usbmodem*"))
        return matches[0] if matches else None
    if os.name == "nt":
        return _find_windows_port()
    return None


def _find_windows_port():
    import winreg
    # Precise: map our VID/PID to its assigned COM port name. A composite
    # enumeration puts the port under an interface key (VID_x&PID_y&MI_zz), so
    # both spellings are searched.
    prefix = "VID_%04X&PID_%04X" % (USB_VID, USB_PID)
    try:
        usb = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Enum\USB")
    except OSError as err:
        debug("cannot read the USB enum key: %s", err)
        usb = None
    if usb is not None:
        for device in _subkeys(usb):
            if not device.upper().startswith(prefix):
                continue
            try:
                parent = winreg.OpenKey(usb, device)
            except OSError:
                continue
            for instance in _subkeys(parent):
                try:
                    params = winreg.OpenKey(parent, instance + r"\Device Parameters")
                    port = winreg.QueryValueEx(params, "PortName")[0]
                except OSError:
                    continue
                debug("found %s under USB\\%s\\%s", port, device, instance)
                return port
            debug("USB\\%s has no PortName under any instance", device)
    # Fallback: the COM ports the system knows about, USB ones first. Anything
    # here may be a modem or a motherboard port, so it is a guess by design.
    ports = _serialcomm_ports()
    debug("no VID/PID match; SERIALCOMM lists %s", ports or "nothing")
    for name, port in ports:
        if "USBSER" in name.upper() or "VCP" in name.upper():
            return port
    return ports[0][1] if ports else None


def _subkeys(key):
    import winreg
    names = []
    try:
        for i in range(winreg.QueryInfoKey(key)[0]):
            names.append(winreg.EnumKey(key, i))
    except OSError:
        pass
    return names


def _serialcomm_ports():
    """[(device name, COM port)] from the SERIALCOMM map, e.g. USBSER000 -> COM3."""
    import winreg
    found = []
    try:
        serialcomm = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    r"HARDWARE\DEVICEMAP\SERIALCOMM")
        for i in range(winreg.QueryInfoKey(serialcomm)[1]):
            name, port, _ = winreg.EnumValue(serialcomm, i)
            found.append((name, port))
    except OSError as err:
        debug("cannot read SERIALCOMM: %s", err)
    return found


# ---------------------------------------------------------------------------
# Client-side validation (before send). Put handlers silently truncate and
# DEL_WWWFILL rejects over-length input, so we never send anything invalid.
# ---------------------------------------------------------------------------

def validate_restricted(value, maxlen, allow_empty, dots_ok=True):
    if not value and not allow_empty:
        return "Required."
    if latin1_safe(value) is None:
        return "Only Latin-1 characters are allowed."
    if len(value.encode("latin-1")) > maxlen:
        return "Too long (max %d)." % maxlen
    for ch in value:
        if ch == "." and dots_ok:
            continue
        if ch not in LABEL_CHARSET:
            return "Character %r is not allowed here." % ch
    return None


def latin1_safe(value):
    try:
        return value.encode("latin-1")
    except UnicodeEncodeError:
        return None


def validate_freeform(value, maxlen, allow_empty=True):
    if not value and not allow_empty:
        return "Required."
    if latin1_safe(value) is None:
        return "Only Latin-1 characters are allowed."
    if len(value.encode("latin-1")) > maxlen:
        return "Too long (max %d)." % maxlen
    return None


def normalize_domain(text):
    """Reduce a URL to the bare host the device stores (strip scheme/port/path)."""
    text = text.strip()
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0]
    text = text.split(":", 1)[0]
    return text


# The device folds a domain's case byte by byte, lowering ONLY ASCII A-Z and
# the six two-case Latin-1 letters its charset permits - Ä Å Æ Ö Ø Ü; every
# other byte, including ß, compares exact. Python's str comparisons disagree
# with that: casefold() maps ß -> "ss" (so "straße.de" would wrongly equal
# "strasse.de" - both are dialog-legal domains) and lower() folds all Latin-1
# uppercase (É -> é), which matters for domains other tools already stored on
# the device. So fold at the byte level with the device's exact table.
_LATIN1_CASE_PAIRS = {0xC4: 0xE4, 0xC5: 0xE5, 0xC6: 0xE6,   # Ä Å Æ
                      0xD6: 0xF6, 0xD8: 0xF8, 0xDC: 0xFC}   # Ö Ø Ü
_LATIN1_FOLD = bytes(b + 0x20 if 0x41 <= b <= 0x5A
                     else _LATIN1_CASE_PAIRS.get(b, b) for b in range(256))


def latin1_fold(text):
    """Lowercase a domain exactly as the device does (bytes out)."""
    return text.encode("latin-1").translate(_LATIN1_FOLD)


def wwwfill_key(domain, username):
    """The device's wwwfill uniqueness key: the domain compares under the
    device's own case fold (see _LATIN1_FOLD above), the username byte-exact.
    Any client-side duplicate logic must use exactly these semantics to agree
    with the device."""
    return (latin1_fold(domain), username)


def wwwfill_duplicate_error(pairs, domain, username, skip=None):
    """Refuse a wwwfill write that would duplicate an existing entry.

    `pairs` is the device's current set of (domain, username) pairs; `skip`
    is the old identity of the pair being edited, so an unchanged edit does
    not collide with itself - but only one occurrence is skipped, so an edit
    of a pair the device already holds twice (the dangerous state) is still
    refused. Returns a message to show the user, or None when the write is
    safe to send. Gated by ENFORCE_WWWFILL_DEDUP; see the comment there.
    """
    if not ENFORCE_WWWFILL_DEDUP:
        return None
    new_key = wwwfill_key(domain, username)
    skip_key = wwwfill_key(*skip) if skip is not None else None
    skipped = False
    for pair in pairs:
        if wwwfill_key(*pair) != new_key:
            continue
        if skip_key == new_key and not skipped:
            skipped = True   # the row being edited itself
            continue
        return ("A web password for %s / %s already exists (domains match "
                "case-insensitively). Duplicates can lock up Seclave firmware "
                "2.6 and earlier, so it was not sent."
                % (pair[0], pair[1]))
    return None


def find_wwwfill_duplicates(pairs):
    """Return one representative (domain, username) per pair stored more than
    once under the device's uniqueness key. A duplicate already on the device
    means an affected firmware (2.6 or earlier) admitted it - the state from
    which an edit can lock up the device - so the UI warns about it at load
    time, the one case the pre-send refusal cannot prevent."""
    counts = {}
    for pair in pairs:
        key = wwwfill_key(*pair)
        counts[key] = counts.get(key, 0) + 1
    reported = set()
    duplicates = []
    for pair in pairs:
        key = wwwfill_key(*pair)
        if counts[key] > 1 and key not in reported:
            reported.add(key)
            duplicates.append(pair)
    return duplicates


# ---------------------------------------------------------------------------
# DeviceSession - high-level commands. Each builds a frame, sends it, and reads
# the reply into the transport's mmap arena until it parses. Every command wipes
# the arena when it finishes (the `finally` blocks below), so secret bytes never
# outlive the command in the arena. Confirmable commands block inside recv()
# until the user acts on the device; ABORT means they declined.
# ---------------------------------------------------------------------------

class DeviceError(Exception):
    def __init__(self, status):
        super().__init__(STATUS_MESSAGE.get(status, "Device error %d." % status))
        self.status = status


class DeviceSession:
    def __init__(self, transport):
        self.transport = transport

    def _exchange(self, payload, field_count):
        """Send one command and read its unframed reply into the arena. Returns
        (status, spans, view); the spans index into `view`, a memoryview over the
        arena. The caller must read what it needs and then wipe the arena."""
        self.transport.write(build_frame(payload))
        self.transport.begin_recv()
        while True:
            view = self.transport.recv()
            parsed = parse_response(view, field_count)
            if parsed is not None:
                status, spans = parsed
                return status, spans, view

    # --- enumerations: confirm once on the device, then stream ---

    def list_labels(self):
        labels = []
        index = 0
        while True:
            payload = bytes([OP_GET_LABELIDX]) + encode_int(index)
            try:
                status, spans, view = self._exchange(payload, 1)
                if status == ST_OUT_OF_INDEX:
                    return labels
                if status == ST_ABORT:
                    raise Cancelled
                if status != ST_OK:
                    raise DeviceError(status)
                (start, end), = spans
                labels.append(bytes(view[start:end]).decode("latin-1"))
            finally:
                self.transport.wipe()
            index += 1

    def list_wwwfill(self):
        rows = []
        index = 0
        while True:
            payload = bytes([OP_GET_WWWFILLIDX]) + encode_int(index)
            try:
                status, spans, view = self._exchange(payload, 2)
                if status == ST_OUT_OF_INDEX:
                    return rows
                if status == ST_ABORT:
                    raise Cancelled
                if status != ST_OK:
                    raise DeviceError(status)
                (ds, de), (us, ue) = spans
                rows.append((bytes(view[ds:de]).decode("latin-1"),
                             bytes(view[us:ue]).decode("latin-1")))
            finally:
                self.transport.wipe()
            index += 1

    # --- per-entry reads. Each is a single field keyed by label. ---

    def get_group(self, label):
        # Group and optional are not secrets: they hold a category or free-form
        # notes/domain and are shown in the table, so a plain str is fine.
        return self._get_text(OP_GET_GROUP, label)

    def get_optional(self, label):
        return self._get_text(OP_GET_OPTIONAL, label)

    def _get_text(self, opcode, label):
        payload = bytes([opcode]) + encode_field(latin1(label))
        try:
            status, spans, view = self._exchange(payload, 1)
            if status == ST_ABORT:
                raise Cancelled
            if status != ST_OK:
                raise DeviceError(status)
            (start, end), = spans
            return bytes(view[start:end]).decode("latin-1")
        finally:
            self.transport.wipe()

    def _get_secret(self, opcode, label):
        payload = bytes([opcode]) + encode_field(latin1(label))
        try:
            status, spans, view = self._exchange(payload, 1)
            if status == ST_ABORT:
                raise Cancelled
            if status != ST_OK:
                raise DeviceError(status)
            (start, end), = spans
            # mmap-to-mmap copy: the secret goes straight from the arena into a
            # SecretBuffer, then the arena is wiped in the finally below.
            return SecretBuffer(view[start:end])
        finally:
            self.transport.wipe()

    def get_username(self, label):
        return self._get_secret(OP_GET_USERNAME, label)

    def get_password(self, label):
        return self._get_secret(OP_GET_PASSWORD, label)

    def get_wwwfill(self, domain, index):
        """Return (username, password, more) for the index-th login on a domain.
        `more` is True when higher indices hold further logins."""
        payload = bytes([OP_GET_WWWFILL]) + encode_field(latin1(domain)) + \
            encode_int(index)
        try:
            status, spans, view = self._exchange(payload, 2)
            if status == ST_ABORT:
                raise Cancelled
            if status not in (ST_OK, ST_MORE_LABELS):
                raise DeviceError(status)
            (us, ue), (ps, pe) = spans
            username = SecretBuffer(view[us:ue])
            password = SecretBuffer(view[ps:pe])
            return username, password, status == ST_MORE_LABELS
        finally:
            self.transport.wipe()

    # --- mutations. Puts/dels return only a status. ---

    def _status_only(self, payload):
        try:
            status, _, _ = self._exchange(payload, 0)
            if status == ST_ABORT:
                raise Cancelled
            if status != ST_OK:
                raise DeviceError(status)
        finally:
            self.transport.wipe()

    def put_entry(self, label, group, username, password, optional):
        payload = bytes([OP_PUT_ENTRY]) + encode_field(latin1(label)) + \
            encode_field(latin1(group)) + encode_field(latin1(username)) + \
            encode_field(latin1(password)) + encode_field(latin1(optional))
        self._status_only(payload)

    def put_wwwfill(self, domain, username, password):
        # Defense in depth: never send a domain outside the charset the device
        # accepts (an embedded NUL is the dangerous case). The dialog validates
        # this already; this guards non-GUI callers such as future bulk-import
        # tooling.
        if validate_restricted(domain, MAX_OPTIONAL, False):
            raise DeviceError(ST_BAD_DOMAIN)
        payload = bytes([OP_PUT_WWWFILL]) + encode_field(latin1(domain)) + \
            encode_field(latin1(username)) + encode_field(latin1(password))
        self._status_only(payload)

    def del_entry(self, label):
        self._status_only(bytes([OP_DEL_ENTRY]) + encode_field(latin1(label)))

    def del_wwwfill(self, domain, username):
        payload = bytes([OP_DEL_WWWFILL]) + encode_field(latin1(domain)) + \
            encode_field(latin1(username))
        self._status_only(payload)


# ---------------------------------------------------------------------------
# Worker thread. It owns the port; the UI never touches the fd. Requests come in
# on a queue, results/events go out on another, drained by the Tk mainloop.
# ---------------------------------------------------------------------------

class Request:
    def __init__(self, name, **data):
        self.name = name
        self.data = data


class Event:
    def __init__(self, name, **data):
        self.name = name
        self.data = data


class Worker(threading.Thread):
    """The single serial thread. Method names here must not collide with
    threading.Thread's own attributes: an instance attribute on the base class
    shadows a method defined here, and the base class grows new ones between
    Python releases (3.13 added `_handle`)."""

    def __init__(self, out_queue):
        super().__init__(daemon=True)
        self.inq = queue.Queue()
        self.outq = out_queue
        self.transport = None
        self.session = None

    def submit(self, name, **data):
        self.inq.put(Request(name, **data))

    def wake(self):
        if self.transport is not None:
            self.transport.wake()

    def emit(self, name, **data):
        self.outq.put(Event(name, **data))

    def run(self):
        while True:
            req = self.inq.get()
            if req.name == "quit":
                self._drop()
                return
            try:
                self._dispatch(req)
            except Cancelled:
                self.emit("declined", request=req.name)
            except Disconnected:
                self._drop()
                self.emit("disconnected")
            except DeviceError as err:
                self.emit("error", message=str(err), status=err.status)
            except Exception as err:
                # Anything unforeseen: report it and keep serving. A thread that
                # dies here leaves the UI waiting for an event that never comes.
                debug("worker failed on %s: %s: %s", req.name,
                      type(err).__name__, err)
                self._drop()
                self.emit("failed", request=req.name,
                          message="%s: %s" % (type(err).__name__, err))

    def _drop(self):
        if self.transport is not None:
            self.transport.close()
        self.transport = None
        self.session = None

    def _dispatch(self, req):
        name = req.name
        if name == "open":
            self.transport = open_serial(req.data["port"])
            self.transport.open()
            self.session = DeviceSession(self.transport)
            self.emit("connected", port=req.data["port"])

        elif name == "close":
            self._drop()
            self.emit("disconnected")

        elif name == "load_labels":
            self.emit("loaded_labels", labels=self.session.list_labels())

        elif name == "load_web":
            self.emit("loaded_web", web=self.session.list_wwwfill())

        elif name == "copy_field":
            label, field = req.data["label"], req.data["field"]
            getter = {"username": self.session.get_username,
                      "password": self.session.get_password,
                      "optional": self.session.get_optional}[field]
            self.emit("secret", label=label, field=field, secret=getter(label))

        elif name == "copy_wwwfill":
            user, pw, _ = self.session.get_wwwfill(req.data["domain"],
                                                   req.data["index"])
            if req.data["field"] == "username":
                pw.clear()
                self.emit("secret", label=req.data["domain"], field="username",
                          secret=user)
            else:
                user.clear()
                self.emit("secret", label=req.data["domain"], field="password",
                          secret=pw)

        elif name == "get_optional":
            value = self.session.get_optional(req.data["label"])
            self.emit("optional", label=req.data["label"], value=value)

        elif name == "fetch_entry":
            # Every field of one entry, for the edit prefill and the viewer.
            # In Normal mode each read is its own device confirmation. On any
            # failure part-way, clear what was already fetched.
            label = req.data["label"]
            group = self.session.get_group(label)
            username = self.session.get_username(label)
            try:
                password = self.session.get_password(label)
                try:
                    optional = self.session.get_optional(label)
                except BaseException:
                    password.clear()
                    raise
            except BaseException:
                username.clear()
                raise
            self.emit("entry_fields", label=label, group=group,
                      username=username, password=password, optional=optional,
                      purpose=req.data["purpose"])

        elif name == "fetch_wwwfill":
            # The table already shows the domain and username; only the
            # password needs fetching.
            user, pw, _ = self.session.get_wwwfill(req.data["domain"],
                                                   req.data["index"])
            user.clear()
            self.emit("wwwfill_fields", domain=req.data["domain"],
                      username=req.data["username"], password=pw,
                      purpose=req.data["purpose"])

        elif name == "put_entry":
            self.session.put_entry(**req.data)
            self.emit("saved", view="labels")

        elif name == "put_wwwfill":
            self.session.put_wwwfill(**req.data)
            self.emit("saved", view="web")

        elif name == "edit_entry":
            # Editing is delete-then-add rather than a plain put onto an existing
            # label. A put onto an existing label triggers the device's own
            # "replace?" prompt, and if the user declines it the device sends no
            # reply at all - the host read would block forever. Deleting first
            # avoids that path and gives a definite status for every command.
            self.session.del_entry(req.data["old_label"])
            fields = {k: req.data[k] for k in
                      ("label", "group", "username", "password", "optional")}
            self.session.put_entry(**fields)
            self.emit("saved", view="labels")

        elif name == "edit_wwwfill":
            self.session.del_wwwfill(req.data["old_domain"],
                                     req.data["old_username"])
            self.session.put_wwwfill(req.data["domain"], req.data["username"],
                                     req.data["password"])
            self.emit("saved", view="web")

        elif name == "del_entry":
            self.session.del_entry(req.data["label"])
            self.emit("saved", view="labels")

        elif name == "del_wwwfill":
            self.session.del_wwwfill(req.data["domain"], req.data["username"])
            self.emit("saved", view="web")


# ---------------------------------------------------------------------------
# Password generator (used by the Add/Edit dialog).
# ---------------------------------------------------------------------------

GEN_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*-_=+"


def generate_password(length):
    return "".join(secrets.choice(GEN_ALPHABET) for _ in range(length))


# ---------------------------------------------------------------------------
# UI. Guarded so the protocol layer above can be imported and tested even where
# tkinter is not installed.
# ---------------------------------------------------------------------------

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
    import tkinter.font as tkfont
    HAVE_TK = True
except ImportError:
    HAVE_TK = False


if HAVE_TK:

    def resolve_mono(root):
        available = set(tkfont.families(root))
        for family in MONO_FAMILIES:
            if family in available:
                return family
        return "TkFixedFont"

    def apply_theme(root, mono):
        style = ttk.Style(root)
        style.theme_use("clam")
        base = (mono, 11)
        bold = (mono, 11, "bold")
        root.configure(background=STYLE["bg"])
        style.configure(".", font=base, background=STYLE["bg"],
                        foreground=STYLE["body"])
        style.configure("TFrame", background=STYLE["bg"])
        style.configure("TLabel", background=STYLE["bg"], foreground=STYLE["body"])
        style.configure("Heading.TLabel", foreground=STYLE["heading"], font=bold)
        style.configure("Muted.TLabel", foreground=STYLE["muted"])
        style.configure("TButton", padding=6)
        style.map("TButton",
                  foreground=[("active", STYLE["white"])],
                  background=[("active", STYLE["blue_hover"])])
        # The single call-to-action button is green; everything else is neutral.
        style.configure("CTA.TButton", foreground=STYLE["white"],
                        background=STYLE["green"], font=bold)
        style.map("CTA.TButton", background=[("active", STYLE["blue_hover"])])
        style.configure("Treeview", rowheight=24, fieldbackground=STYLE["bg"],
                        background=STYLE["bg"], foreground=STYLE["body"])
        style.configure("Treeview.Heading", font=bold,
                        background=STYLE["blue"], foreground=STYLE["white"])
        style.map("Treeview",
                  background=[("selected", STYLE["blue"])],
                  foreground=[("selected", STYLE["white"])])
        style.configure("Status.TLabel", background=STYLE["bg"],
                        foreground=STYLE["muted"])
        return style

    def draw_key_mark(canvas):
        """The key mark as simple vectors: brushed ring, blue lens, shaft with
        two notches. A small self-contained stand-in for a logo image."""
        canvas.create_oval(6, 6, 30, 30, outline=STYLE["muted"], width=3)
        canvas.create_oval(12, 12, 24, 24, fill=STYLE["blue"], outline="")
        canvas.create_oval(14, 14, 18, 18, fill=STYLE["white"], outline="")  # glint
        canvas.create_line(28, 18, 52, 18, fill=STYLE["muted"], width=3)
        canvas.create_line(44, 18, 44, 25, fill=STYLE["muted"], width=3)
        canvas.create_line(50, 18, 50, 24, fill=STYLE["muted"], width=3)

    class EntryDialog(tk.Toplevel):
        """Add or edit an entry. `existing` is None for Add, or a dict for Edit."""

        def __init__(self, parent, mono, on_save, existing=None):
            super().__init__(parent)
            self.on_save = on_save
            self.existing = existing
            self.mono = mono
            self.title("Edit entry" if existing else "Add entry")
            self.configure(background=STYLE["bg"])
            self.transient(parent)
            self.resizable(False, False)
            self.is_web = tk.BooleanVar(value=bool(existing and existing.get("web")))
            self.vars = {k: tk.StringVar() for k in
                         ("label", "group", "username", "password", "optional",
                          "domain")}
            self.show_pw = tk.BooleanVar(value=False)
            self._build()
            if existing:
                self._load_existing(existing)
                self.error.configure(
                    text="Saving replaces the entry: delete then add, each "
                         "step confirmed on the device.",
                    foreground=STYLE["muted"])
            self._refresh_fields()
            self.grab_set()

        def _build(self):
            pad = {"padx": 8, "pady": 4}
            top = ttk.Frame(self)
            top.grid(row=0, column=0, columnspan=3, sticky="w", **pad)
            ttk.Label(top, text="Type:").pack(side="left")
            ttk.Radiobutton(top, text="Regular", variable=self.is_web, value=False,
                            command=self._refresh_fields).pack(side="left", padx=6)
            ttk.Radiobutton(top, text="Web password", variable=self.is_web,
                            value=True, command=self._refresh_fields).pack(side="left")
            if self.existing:
                # Type is fixed when editing an existing entry.
                for child in top.winfo_children():
                    if isinstance(child, ttk.Radiobutton):
                        child.configure(state="disabled")

            self.rows = {}
            self._add_row("label", "Label", 1, MAX_LABEL)
            self._add_row("domain", "Domain", 1, MAX_OPTIONAL)
            self._add_row("group", "Group", 2, MAX_GROUP)
            self._add_row("username", "Username", 3, MAX_USERNAME)
            self._add_row("password", "Password", 4, MAX_PASSWORD, secret=True)
            self._add_row("optional", "Optional", 5, MAX_OPTIONAL)

            btns = ttk.Frame(self)
            btns.grid(row=7, column=0, columnspan=3, sticky="e", **pad)
            ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right")
            self.save_btn = ttk.Button(btns, text="Save (device)",
                                       style="CTA.TButton", command=self._save)
            self.save_btn.pack(side="right", padx=6)

            self.error = ttk.Label(self, style="Muted.TLabel", text="")
            self.error.grid(row=6, column=0, columnspan=3, sticky="w", **pad)

        def _add_row(self, key, label, row, maxlen, secret=False):
            lbl = ttk.Label(self, text=label)
            entry = ttk.Entry(self, textvariable=self.vars[key], width=40,
                              font=(self.mono, 11))
            counter = ttk.Label(self, style="Muted.TLabel", text="0/%d" % maxlen)
            lbl.grid(row=row, column=0, sticky="w", padx=8, pady=4)
            entry.grid(row=row, column=1, sticky="w", padx=8, pady=4)
            counter.grid(row=row, column=2, sticky="w", padx=8, pady=4)
            self.vars[key].trace_add("write", lambda *_: self._update_counter(
                key, entry, counter, maxlen))
            self.rows[key] = (lbl, entry, counter)
            if secret:
                entry.configure(show="*")
                extra = ttk.Frame(self)
                extra.grid(row=row, column=3, sticky="w")
                ttk.Checkbutton(extra, text="show", variable=self.show_pw,
                                command=lambda: entry.configure(
                                    show="" if self.show_pw.get() else "*")
                                ).pack(side="left")
                for n in (8, 12, 16, 20):
                    ttk.Button(extra, text=str(n), width=3,
                               command=lambda n=n: self.vars["password"].set(
                                   generate_password(n))).pack(side="left")

        def _update_counter(self, key, entry, counter, maxlen):
            # Red from the moment the field is full: one more character and the
            # device truncates silently (its put handlers copy MIN(sent, field
            # width)), so the warning has to come before the loss, not after.
            used = len(self.vars[key].get().encode("latin-1", "ignore"))
            colour = STYLE["red"] if used >= maxlen else STYLE["muted"]
            counter.configure(text="%d/%d" % (used, maxlen), foreground=colour)
            entry.configure(foreground=colour if used >= maxlen
                            else STYLE["body"])

        def _refresh_fields(self):
            web = self.is_web.get()
            shown = {"domain", "username", "password"} if web else \
                {"label", "group", "username", "password", "optional"}
            for key, (lbl, entry, counter) in self.rows.items():
                state = "normal" if key in shown else "hidden"
                for widget in (lbl, entry, counter):
                    if state == "hidden":
                        widget.grid_remove()
                    else:
                        widget.grid()

        def _load_existing(self, existing):
            for key, value in existing.items():
                if key in self.vars and value is not None:
                    self.vars[key].set(value)

        def _save(self):
            if self.is_web.get():
                domain = normalize_domain(self.vars["domain"].get())
                errors = [validate_restricted(domain, MAX_OPTIONAL, False),
                          validate_freeform(self.vars["username"].get(),
                                            MAX_USERNAME, allow_empty=False),
                          validate_freeform(self.vars["password"].get(),
                                            MAX_PASSWORD, allow_empty=False)]
                data = {"web": True, "domain": domain,
                        "username": self.vars["username"].get(),
                        "password": self.vars["password"].get()}
            else:
                errors = [validate_restricted(self.vars["label"].get(),
                                              MAX_LABEL, False),
                          validate_restricted(self.vars["group"].get(),
                                              MAX_GROUP, True),
                          validate_freeform(self.vars["username"].get(),
                                            MAX_USERNAME),
                          validate_freeform(self.vars["password"].get(),
                                            MAX_PASSWORD),
                          validate_freeform(self.vars["optional"].get(),
                                            MAX_OPTIONAL)]
                data = {"web": False}
                for key in ("label", "group", "username", "password", "optional"):
                    data[key] = self.vars[key].get()
            problem = next((e for e in errors if e), None)
            if problem is None:
                # The app-level save can refuse too (the wwwfill duplicate
                # check): it returns a message to show, or None once the
                # request is on its way to the device.
                problem = self.on_save(data, self.existing)
            if problem:
                self.error.configure(text=problem, foreground=STYLE["blue_hover"])
                return
            self.destroy()

    class EntryViewer(tk.Toplevel):
        """Read-only view of every field of one entry. The values are
        selectable; the password stays masked until "show" is ticked. Nothing
        here is cached - the window holds the only host-side copy, gone when
        it closes."""

        def __init__(self, parent, mono, fields):
            super().__init__(parent)
            self.title(fields.get("label") or fields.get("domain") or "Entry")
            self.configure(background=STYLE["bg"])
            self.transient(parent)
            self.resizable(False, False)
            self.show_pw = tk.BooleanVar(value=False)
            if fields.get("web"):
                rows = [("Domain", "domain"), ("Username", "username"),
                        ("Password", "password")]
            else:
                rows = [("Label", "label"), ("Group", "group"),
                        ("Username", "username"), ("Password", "password"),
                        ("Optional", "optional")]
            self.vars = []   # keep refs: a GC'd StringVar empties its widget
            for i, (title, key) in enumerate(rows):
                ttk.Label(self, text=title).grid(row=i, column=0, sticky="w",
                                                 padx=8, pady=4)
                var = tk.StringVar(value=fields.get(key) or "")
                self.vars.append(var)
                entry = ttk.Entry(self, textvariable=var, width=40,
                                  font=(mono, 11), state="readonly")
                entry.grid(row=i, column=1, sticky="w", padx=8, pady=4)
                if key == "password":
                    entry.configure(show="*")
                    ttk.Checkbutton(
                        self, text="show", variable=self.show_pw,
                        command=lambda e=entry: e.configure(
                            show="" if self.show_pw.get() else "*")
                    ).grid(row=i, column=2, sticky="w", padx=4)
            ttk.Button(self, text="Close", command=self.destroy).grid(
                row=len(rows), column=1, sticky="e", padx=8, pady=8)
            self.bind("<Escape>", lambda e: self.destroy())
            self.grab_set()

    class App(tk.Tk):
        def __init__(self, forced_port=None):
            super().__init__()
            self.forced_port = forced_port
            self.last_seen_port = False   # False = not polled yet, None = nothing found
            self.title("Seclave Companion")
            self.mono = resolve_mono(self)
            apply_theme(self, self.mono)

            self.events = queue.Queue()
            self.worker = Worker(self.events)
            self.worker.start()

            self.connected = False
            self.busy = False
            self.view = "labels"          # or "web"
            self.label_rows = []          # list of dicts
            self.web_rows = []
            # Each view's entries are enumerated lazily and independently - one
            # device confirmation each - and only the first time this session.
            self.labels_loaded = False
            self.web_loaded = False
            self.sort_col = None
            self.sort_desc = False
            self.clip_value = None
            self.clip_after = None
            self.reveal_after = None

            self._build_ui()
            # Open at the preferred size below. The widgets' own requested size
            # is used only as a minimum, so the layout never clips when the
            # desktop scales fonts (common on Wayland/HiDPI) - but the preferred
            # size is honored whenever it clears that minimum.
            self.update_idletasks()
            self.minsize(self.winfo_reqwidth(), self.winfo_reqheight())
            width, height = WINDOW_SIZE
            width = max(width, self.winfo_reqwidth())
            height = max(height, self.winfo_reqheight())
            self.geometry("%dx%d" % (width, height))
            self.protocol("WM_DELETE_WINDOW", self._on_close)
            self.after(50, self._poll_events)
            self.after(200, self._poll_port)

        # ---- layout ----

        def _build_ui(self):
            header = ttk.Frame(self, padding=(10, 8))
            header.pack(fill="x")
            canvas = tk.Canvas(header, width=60, height=36, highlightthickness=0,
                               background=STYLE["bg"])
            draw_key_mark(canvas)
            canvas.pack(side="left")
            ttk.Label(header, text="seclave", font=(self.mono, 16, "bold"),
                      foreground=STYLE["heading"]).pack(side="left")
            ttk.Label(header, text="companion", font=(self.mono, 16),
                      foreground=STYLE["blue"]).pack(side="left")
            self.conn_label = ttk.Label(header, text="● disconnected",
                                        style="Muted.TLabel")
            self.conn_label.pack(side="right")
            ttk.Button(header, text="Help", command=self._show_help
                       ).pack(side="right", padx=6)

            toolbar = ttk.Frame(self, padding=(10, 4))
            toolbar.pack(fill="x")
            self.load_btn = ttk.Button(toolbar, text="Load view",
                                       style="CTA.TButton", command=self._load)
            self.load_btn.pack(side="left")
            self.add_btn = ttk.Button(toolbar, text="+ Add", command=self._add)
            self.add_btn.pack(side="left", padx=4)
            self.edit_btn = ttk.Button(toolbar, text="Edit", command=self._edit)
            self.edit_btn.pack(side="left", padx=4)
            self.show_entry_btn = ttk.Button(toolbar, text="Show entry",
                                             command=self._show_entry)
            self.show_entry_btn.pack(side="left", padx=4)
            self.del_btn = ttk.Button(toolbar, text="Delete", command=self._delete)
            self.del_btn.pack(side="left", padx=4)
            self.copy_user_btn = ttk.Button(toolbar, text="Copy username",
                                            command=lambda: self._copy("username"))
            self.copy_user_btn.pack(side="left", padx=4)
            self.copy_pw_btn = ttk.Button(toolbar, text="Copy password",
                                          command=lambda: self._copy("password"))
            self.copy_pw_btn.pack(side="left", padx=4)
            self.copy_opt_btn = ttk.Button(toolbar, text="Copy optional",
                                           command=self._copy_optional)
            self.copy_opt_btn.pack(side="left", padx=4)

            ttk.Label(toolbar, text="Group:").pack(side="left", padx=(12, 2))
            self.group_var = tk.StringVar(value="All labels")
            self.group_box = ttk.Combobox(
                toolbar, textvariable=self.group_var, state="readonly", width=22,
                values=["All labels", "Web passwords (wwwfill)"])
            self.group_box.pack(side="left")
            self.group_box.bind("<<ComboboxSelected>>", lambda e: self._switch_view())

            search = ttk.Frame(self, padding=(10, 2))
            search.pack(fill="x")
            ttk.Label(search, text="Search:").pack(side="left")
            self.search_var = tk.StringVar()
            entry = ttk.Entry(search, textvariable=self.search_var, width=40,
                              font=(self.mono, 11))
            entry.pack(side="left", padx=6)
            entry.bind("<KeyRelease>", lambda e: self._render())
            self.count_label = ttk.Label(search, text="0 entries",
                                         style="Muted.TLabel")
            self.count_label.pack(side="right")

            table = ttk.Frame(self, padding=(10, 4))
            table.pack(fill="both", expand=True)
            self.tree = ttk.Treeview(table, show="headings", selectmode="browse")
            scroll = ttk.Scrollbar(table, orient="vertical",
                                   command=self.tree.yview)
            self.tree.configure(yscrollcommand=scroll.set)
            scroll.pack(side="right", fill="y")
            self.tree.pack(side="left", fill="both", expand=True)
            self.tree.bind("<Double-1>", lambda e: self._copy("password"))
            self._configure_columns()

            # The alert bar: red while something needs the user (usually a
            # confirmation on the device), with a green leading dot. Two plain
            # tk labels because one label cannot hold two colours.
            self.wait_bar = tk.Frame(self, background=STYLE["bg"])
            self.wait_dot = tk.Label(self.wait_bar, text="",
                                     background=STYLE["bg"],
                                     foreground=STYLE["green"],
                                     font=(self.mono, 11, "bold"))
            self.wait_dot.pack(side="left", padx=(10, 4), pady=4)
            self.wait_text = tk.Label(self.wait_bar, text="",
                                      background=STYLE["bg"],
                                      foreground=STYLE["white"], anchor="w",
                                      font=(self.mono, 11, "bold"))
            self.wait_text.pack(side="left", fill="x", expand=True, pady=4)
            self.wait_bar.pack(fill="x", side="bottom")
            self.status = ttk.Label(self, text="Starting...", style="Status.TLabel",
                                    anchor="w", padding=(10, 4))
            self.status.pack(fill="x", side="bottom")
            self._update_actions()

        def _configure_columns(self):
            if self.view == "web":
                cols = [("domain", "Domain", 260), ("username", "Username", 260)]
            else:
                cols = [("label", "Label", 180), ("group", "Group", 110),
                        ("username", "Username", 210), ("optional", "Optional", 210)]
            self.tree.configure(columns=[c[0] for c in cols])
            for key, title, width in cols:
                self.tree.heading(key, text=title,
                                  command=lambda k=key: self._sort_by(k))
                self.tree.column(key, width=width, anchor="w")

        # ---- connection lifecycle ----

        def _poll_port(self):
            if not self.connected:
                port = find_port(self.forced_port)
                if port != self.last_seen_port:
                    debug("discovery: %s", port or "no device")
                    self.last_seen_port = port
                if port:
                    self.worker.submit("open", port=port)
            self.after(1000, self._poll_port)

        def _poll_events(self):
            try:
                while True:
                    self._on_event(self.events.get_nowait())
            except queue.Empty:
                pass
            self.after(50, self._poll_events)

        def _on_event(self, ev):
            handler = getattr(self, "_ev_" + ev.name, None)
            if handler:
                handler(ev.data)

        def _ev_connected(self, data):
            self.connected = True
            self.conn_label.configure(text="● connected",
                                      foreground=STYLE["green"])
            self._set_status("Connected  -  %s  -  click Load view" % data["port"])
            self._update_actions()

        def _ev_disconnected(self, data):
            self.connected = False
            self._end_wait()
            # A new session re-latches on the device, so the next enumeration will
            # prompt again - forget what was loaded (rows stay visible read-only).
            self.labels_loaded = False
            self.web_loaded = False
            self.conn_label.configure(text="● disconnected",
                                      foreground=STYLE["muted"])
            self._set_status('Device disconnected - re-enter "Usb slave" on the '
                             "device to reconnect. Loaded rows stay visible.")
            self._update_actions()

        def _ev_loaded_labels(self, data):
            self._end_wait()
            self.labels_loaded = True
            self.label_rows = [{"label": lbl, "group": None, "username": None,
                                "optional": None} for lbl in data["labels"]]
            self._set_status("Loaded %d labels." % len(self.label_rows))
            self._render()

        def _ev_loaded_web(self, data):
            self._end_wait()
            self.web_loaded = True
            self.web_rows = []
            domain_seen = {}
            for domain, username in data["web"]:
                idx = domain_seen.get(domain, 0)
                domain_seen[domain] = idx + 1
                self.web_rows.append({"domain": domain, "username": username,
                                      "index": idx})
            self._set_status("Loaded %d web passwords." % len(self.web_rows))
            self._render()
            duplicates = find_wwwfill_duplicates(data["web"])
            if duplicates:
                # A duplicate already stored is the one case the pre-send
                # refusal cannot prevent; editing such a row can lock up an
                # affected firmware, so warn the moment it becomes visible.
                names = ", ".join("%s / %s" % pair for pair in duplicates)
                message = ("The device already holds duplicate web passwords "
                           "for: %s. Editing these can lock up Seclave "
                           "firmware 2.6 and earlier - delete the extra "
                           "copies first." % names)
                messagebox.showwarning("Seclave Companion", message)
                self._set_status(message)

        def _ev_secret(self, data):
            secret = data["secret"]
            self._copy_secret(secret)
            self._end_wait()
            self._set_status("Copied %s to clipboard - clears in %d s."
                             % (data["field"], CLIPBOARD_CLEAR_MS // 1000))

        def _ev_optional(self, data):
            # Optional is not a secret, so it also lands in the table and stays
            # until the next reload.
            self._end_wait()
            for row in self.label_rows:
                if row["label"] == data["label"]:
                    row["optional"] = data["value"]
            self._render()
            self._put_clipboard(data["value"])
            self._set_status("Copied optional to clipboard - clears in %d s."
                             % (CLIPBOARD_CLEAR_MS // 1000))

        def _ev_entry_fields(self, data):
            self._end_wait()
            # The str copies below are the documented moment-of-use exception;
            # the SecretBuffers are cleared as soon as they are made.
            username = data["username"].text()
            data["username"].clear()
            password = data["password"].text()
            data["password"].clear()
            # Group, username and optional now stand revealed by the user's own
            # confirmations - reflect them in the table.
            for row in self.label_rows:
                if row["label"] == data["label"]:
                    row["group"] = data["group"]
                    row["username"] = username
                    row["optional"] = data["optional"]
            self._render()
            fields = {"web": False, "label": data["label"],
                      "group": data["group"], "username": username,
                      "password": password, "optional": data["optional"]}
            if data["purpose"] == "edit":
                fields["_old_label"] = data["label"]
                EntryDialog(self, self.mono, self._on_dialog_save,
                            existing=fields)
            else:
                EntryViewer(self, self.mono, fields)

        def _ev_wwwfill_fields(self, data):
            self._end_wait()
            password = data["password"].text()
            data["password"].clear()
            fields = {"web": True, "domain": data["domain"],
                      "username": data["username"], "password": password}
            if data["purpose"] == "edit":
                fields["_old_domain"] = data["domain"]
                fields["_old_username"] = data["username"]
                EntryDialog(self, self.mono, self._on_dialog_save,
                            existing=fields)
            else:
                EntryViewer(self, self.mono, fields)

        def _ev_saved(self, data):
            self._end_wait()
            # Refresh only the view the change touched. Within a session the
            # device latches the first enumeration confirmation, so re-enumerating
            # needs no new prompt.
            if data["view"] == "web":
                self.worker.submit("load_web")
                self._begin_wait("Refreshing web passwords...")
            else:
                self.worker.submit("load_labels")
                self._begin_wait("Refreshing labels...")

        def _ev_declined(self, data):
            self._end_wait()
            self._set_status("Declined on device.")

        def _ev_error(self, data):
            self._end_wait()
            messagebox.showwarning("Seclave Companion", data["message"])
            self._set_status(data["message"])

        def _ev_failed(self, data):
            # Status bar only: the port poll retries once a second, and a dialog
            # per retry would bury the window.
            self.connected = False
            self._end_wait()
            self._set_status("%s failed - %s" % (data["request"], data["message"]))
            self._update_actions()

        # ---- actions ----

        def _load(self):
            # Load (or reload) only the view that is showing - never both. Each
            # enumeration is one device confirmation and matches its on-screen
            # prompt.
            if not self._require_connection():
                return
            if self.view == "web":
                self.web_loaded = False
                self._begin_wait("Loading - look at your Seclave and confirm "
                                 '"Show all wwwfills".')
                self.worker.submit("load_web")
            else:
                self.labels_loaded = False
                self._begin_wait("Loading - look at your Seclave and confirm "
                                 '"Show all labels".')
                self.worker.submit("load_labels")

        def _switch_view(self):
            self.view = "web" if self.group_var.get().startswith("Web") else "labels"
            self.sort_col = None
            self._configure_columns()
            self._render()
            # Enumerate this view the first time it is shown; if it is already
            # loaded this session the switch is purely local (no reconfirm).
            self._ensure_loaded()

        def _ensure_loaded(self):
            if self.busy or not self.connected:
                return
            if self.view == "web" and not self.web_loaded:
                self._begin_wait("Loading - look at your Seclave and confirm "
                                 '"Show all wwwfills".')
                self.worker.submit("load_web")
            elif self.view == "labels" and not self.labels_loaded:
                self._begin_wait("Loading - look at your Seclave and confirm "
                                 '"Show all labels".')
                self.worker.submit("load_labels")

        def _sort_by(self, col):
            self.sort_desc = not self.sort_desc if self.sort_col == col else False
            self.sort_col = col
            self._render()

        def _render(self):
            rows = self.web_rows if self.view == "web" else self.label_rows
            needle = self.search_var.get().lower()
            keys = ("domain", "username") if self.view == "web" else \
                ("label", "group", "username", "optional")
            visible = [r for r in rows
                       if not needle or any(needle in str(r.get(k) or "").lower()
                                            for k in keys)]
            if self.sort_col:
                visible.sort(key=lambda r: str(r.get(self.sort_col) or "").lower(),
                             reverse=self.sort_desc)
            self.tree.delete(*self.tree.get_children())
            self.row_by_iid = {}
            for i, row in enumerate(visible):
                if self.view == "web":
                    values = (row["domain"], row["username"])
                else:
                    values = (row["label"], row["group"] or "•••",
                              row["username"] or "•••", row["optional"] or "•••")
                iid = str(i)
                self.tree.insert("", "end", iid=iid, values=values)
                self.row_by_iid[iid] = row
            self.count_label.configure(text="%d entries" % len(visible))

        def _selected_row(self):
            sel = self.tree.selection()
            if not sel:
                self._set_status("Select a row first.")
                return None
            return self.row_by_iid.get(sel[0])

        def _copy(self, field):
            if not self._require_connection():
                return
            row = self._selected_row()
            if row is None:
                return
            if self.view == "web":
                self._begin_wait("Fetching %s..." % field)
                self.worker.submit("copy_wwwfill", domain=row["domain"],
                                   index=row["index"], field=field)
            else:
                self._begin_wait("Look at your Seclave - confirm showing the "
                                 "%s for %s." % (field, row["label"]))
                self.worker.submit("copy_field", label=row["label"], field=field)

        def _copy_optional(self):
            # Optional is fetched lazily (a confirmable read on the device),
            # never in bulk. Once fetched it stays shown in the table, so a
            # later copy of the same row reuses it without asking the device
            # again.
            if not self._require_connection():
                return
            row = self._selected_row()
            if row is None:
                return
            if self.view == "web":
                # The domain column already is the optional field for web logins.
                self._put_clipboard(row["domain"])
                self._set_status("Copied the domain (the optional field).")
                return
            cached = row.get("optional")
            if cached is not None:
                self._put_clipboard(cached)
                self._set_status("Copied optional to clipboard - clears in "
                                 "%d s." % (CLIPBOARD_CLEAR_MS // 1000))
                return
            self._begin_wait("Look at your Seclave - confirm showing the "
                             "optional for %s." % row["label"])
            self.worker.submit("get_optional", label=row["label"])

        def _add(self):
            if not self._require_connection():
                return
            EntryDialog(self, self.mono, self._on_dialog_save)

        def _edit(self):
            # The dialog opens prefilled once every field has been read from
            # the device (each read confirmed there); see _ev_entry_fields.
            self._fetch_fields("edit")

        def _show_entry(self):
            self._fetch_fields("show")

        def _fetch_fields(self, purpose):
            if not self._require_connection():
                return
            row = self._selected_row()
            if row is None:
                return
            if self.view == "web":
                self._begin_wait("Fetching the password for %s..."
                                 % row["domain"])
                self.worker.submit("fetch_wwwfill", domain=row["domain"],
                                   index=row["index"], username=row["username"],
                                   purpose=purpose)
            else:
                self._begin_wait("Look at your Seclave - confirm reading each "
                                 "field of %s." % row["label"])
                self.worker.submit("fetch_entry", label=row["label"],
                                   purpose=purpose)

        def _delete(self):
            if not self._require_connection():
                return
            row = self._selected_row()
            if row is None:
                return
            name = row.get("label") or row.get("domain")
            if not messagebox.askyesno("Delete entry",
                                       "Delete %r? Confirm on the device too."
                                       % name):
                return
            self._begin_wait("Look at your Seclave - confirm the delete.")
            if self.view == "web":
                self.worker.submit("del_wwwfill", domain=row["domain"],
                                   username=row["username"])
            else:
                self.worker.submit("del_entry", label=row["label"])

        def _on_dialog_save(self, data, existing):
            """Submit a dialog Save to the worker. Returns None when the
            request was sent, or a message for the dialog to show - the entry
            is then not sent and the dialog stays open."""
            if data["web"]:
                problem = self._wwwfill_duplicate_problem(data, existing)
                if problem:
                    return problem
            self._begin_wait("Look at your Seclave - confirm on the device.")
            if data["web"]:
                if existing and "_old_domain" in existing:
                    self.worker.submit(
                        "edit_wwwfill", old_domain=existing["_old_domain"],
                        old_username=existing["_old_username"],
                        domain=data["domain"], username=data["username"],
                        password=data["password"])
                else:
                    self.worker.submit("put_wwwfill", domain=data["domain"],
                                       username=data["username"],
                                       password=data["password"])
            else:
                fields = {k: data[k] for k in
                          ("label", "group", "username", "password", "optional")}
                if existing and "_old_label" in existing:
                    self.worker.submit("edit_entry",
                                       old_label=existing["_old_label"], **fields)
                else:
                    self.worker.submit("put_entry", **fields)
            return None

        def _wwwfill_duplicate_problem(self, data, existing):
            # The duplicate refusal (see ENFORCE_WWWFILL_DEDUP) checks
            # against self.web_rows, which mirrors the device exactly while
            # web_loaded is set: it is filled by each enumeration, refreshed
            # after every web mutation, and web_loaded is cleared on
            # disconnect. When the cache is not known-fresh we neither trust
            # it (that would defeat the check) nor send the write unchecked:
            # we start the normal one-confirmation enumeration and ask the
            # user to press Save again. Re-enumerating silently before every
            # put would instead cost a surprise device confirmation in the
            # stricter access modes.
            if not ENFORCE_WWWFILL_DEDUP:
                return None
            if not self.web_loaded:
                if not self.connected:
                    return ('Not connected - put your Seclave in the '
                            '"Usb slave" menu.')
                if not self.busy:
                    self._begin_wait("Loading - look at your Seclave and "
                                     'confirm "Show all wwwfills".')
                    self.worker.submit("load_web")
                return ("The duplicate check needs the current web password "
                        "list - loading it now. Click Save (device) again "
                        "when it finishes.")
            skip = None
            if existing and "_old_domain" in existing:
                skip = (existing["_old_domain"], existing["_old_username"])
            return wwwfill_duplicate_error(
                [(r["domain"], r["username"]) for r in self.web_rows],
                data["domain"], data["username"], skip=skip)

        # ---- clipboard ----

        def _put_clipboard(self, value):
            self.clipboard_clear()
            self.clipboard_append(value)
            self.clip_value = value
            if self.clip_after:
                self.after_cancel(self.clip_after)
            self.clip_after = self.after(CLIPBOARD_CLEAR_MS, self._clear_clipboard)

        def _copy_secret(self, secret):
            self._put_clipboard(secret.text())
            secret.clear()

        def _clear_clipboard(self):
            self.clip_after = None
            if self.clip_value is None:
                return
            try:
                if self.clipboard_get() == self.clip_value:
                    self.clipboard_clear()
            except tk.TclError:
                pass
            self.clip_value = None

        # ---- shared state helpers ----

        def _require_connection(self):
            if self.busy:
                self._set_status("Wait for the current device action to finish.")
                return False
            if not self.connected:
                self._set_status('Not connected - put your Seclave in the '
                                 '"Usb slave" menu.')
                return False
            return True

        def _begin_wait(self, message):
            self.busy = True
            self.wait_bar.configure(background=STYLE["red"])
            self.wait_dot.configure(text="⬤", background=STYLE["red"])
            self.wait_text.configure(text=message, background=STYLE["red"])
            self._update_actions()

        def _end_wait(self):
            self.busy = False
            self.wait_bar.configure(background=STYLE["bg"])
            self.wait_dot.configure(text="", background=STYLE["bg"])
            self.wait_text.configure(text="", background=STYLE["bg"])
            self._update_actions()

        def _set_status(self, text):
            self.status.configure(text=text)

        def _update_actions(self):
            live = "normal" if (self.connected and not self.busy) else "disabled"
            for btn in (self.load_btn, self.add_btn, self.edit_btn,
                        self.show_entry_btn, self.del_btn, self.copy_user_btn,
                        self.copy_pw_btn, self.copy_opt_btn):
                btn.configure(state=live)

        def _show_help(self):
            messagebox.showinfo(
                "About Seclave Companion",
                "Seclave Companion %s\n\n"
                "A desktop table view for your Seclave 2.0 over its USB-slave "
                "serial protocol. Put the device in its \"Usb slave\" menu, then "
                "click Load view. Labels and web passwords load separately - one "
                "device confirmation each, when you first show that view.\n\n"
                "Access modes: the device may ask you to confirm each read on "
                "its screen (Normal / Ask all), or allow them silently (Allow "
                "all). The app cannot read the current mode, so it always shows "
                "the confirm hint; if the device is set to Allow all it simply "
                "returns at once.\n\n"
                "Web passwords (wwwfill) are read and written without a device "
                "prompt in Normal mode - that path is intentionally "
                "frictionless.\n\n"
                "Secrets are fetched only when you ask, copied to the clipboard, "
                "and the clipboard clears after %d seconds and on exit.\n\n"
                "Show entry reads every field of the selected row (confirming "
                "on the device) into a read-only window; Edit does the same and "
                "opens the dialog prefilled."
                % (VERSION, CLIPBOARD_CLEAR_MS // 1000))

        def _on_close(self):
            self._clear_clipboard()
            self.worker.submit("quit")
            self.worker.wake()
            self.destroy()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Seclave Companion")
    parser.add_argument("--version", action="version",
                        version="Seclave Companion " + VERSION)
    parser.add_argument("--port", help="serial node to use instead of "
                        "auto-discovery (dev/test)")
    parser.add_argument("--debug", action="store_true",
                        help="trace port discovery and the serial open")
    args = parser.parse_args(argv)
    if args.debug:
        enable_debug()
    if not HAVE_TK:
        # tkinter is part of the standard library but is built against the
        # Tcl/Tk C libraries, so it cannot be installed from PyPI: it comes
        # with the interpreter or not at all. Beware of PyPI packages named
        # after it - none of them are official.
        sys.stderr.write(
            "tkinter is not available in this Python (%s).\n"
            "It ships with the interpreter and cannot be pip-installed.\n\n"
            "  Debian/Ubuntu:  sudo apt install python3-tk\n"
            "  Fedora/RHEL:    sudo dnf install python3-tkinter\n"
            "  Arch:           sudo pacman -S tk\n"
            "  macOS Homebrew: brew install python-tk\n"
            "  macOS/Windows:  use the python.org installer, which has it\n"
            % sys.executable)
        return 1
    App(forced_port=args.port).mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())

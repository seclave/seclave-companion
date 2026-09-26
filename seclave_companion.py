#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 Seclave AB
"""Seclave Companion - a desktop table view for a Seclave 2.0 hardware password
manager, over its USB-slave (CDC-ACM serial) protocol.

One self-contained program, Python standard library only: no pip installs, no
sockets, no IPC. Connect the device, put it in its "Usb slave" menu, and this
app enumerates the entries into a searchable, sortable table and lets you copy a
username or password, add/edit/delete an entry, or export the device's
encrypted backup to a file - each secret action honoring the device's on-screen
confirmation. Entries can be added in bulk from a JSON file; a backup archive
can be opened offline with its backup key, viewed read-only, and exported to
JSON, CSV or YAML.

Read this file top to bottom; each section depends only on the ones above it:

    constants / style tokens
    SecretBuffer          - zeroizable landing zone for secret bytes
    protocol codec        - integer/field encoding, response parsing
    backup archive        - offline AES-128, archive decrypt/verify, exporters
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
import csv
import glob
import json
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
VERSION = "1.3.1"

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
OP_QUERY_STATUS = 13        # 2.7+ only - probe with VERSION_DOMAIN first
OP_GET_LABELGROUPIDX = 14   # 2.7+ only - the label enumeration with the group

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

# The entry fields the table can show besides the label, in column order. The
# password is deliberately not among them: it is fetched to the clipboard or a
# viewer and never held in a row.
TABLE_FIELDS = ("group", "username", "optional")

# The tabled fields treated as sensitive: Hide fields masks them and a detach
# forgets them. Label and group stay through both - they are what keeps a row
# findable.
SENSITIVE_FIELDS = ("username", "optional")

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

# GET_BACKUP streams the device's backup as 224-byte encrypted items: 500
# record slots and then one backup header, indices 0..500, until the device
# answers OUT_OF_INDEX. The device's own mass-storage export (SECLAVE.BKP)
# holds each item zero-padded into a 256-byte slot, and the restore flow reads
# that layout back - so the export here writes exactly those bytes. The archive
# is opaque ciphertext under the device's backup key: never parsed here, and
# unreadable without the key, which never leaves the device.
BACKUP_BLOB_SIZE = 224
BACKUP_SLOT_SIZE = 256
BACKUP_ITEMS = MAX_ENTRIES + 1   # the 500 record slots plus the header
BACKUP_ENC_SIZE = 208            # the encrypted, MACed prefix of each item


def default_backup_filename():
    """Dated, so repeated exports collect side by side instead of silently
    overwriting the previous one. The device's own mass-storage export is
    always named SECLAVE.BKP; the format is the same."""
    return time.strftime("seclave_%Y_%m_%d.bkp")

WWWFILL_GROUP = "wwwfill"

# Firmware discovery is two-stage. The probe: reading this reserved
# web-password domain (index 0) is promptless and harmless on every
# firmware - 2.7 and later intercept it and answer the marker below
# (plus one empty field), while 2.6 and earlier know no such domain and
# answer "entry not found". That single bit says whether the canonical
# QUERY_STATUS command exists; probing with an unknown command instead
# is NOT safe (firmware treats it as a parse error and leaves slave
# mode). The \xf6 prefix is o-umlaut in Latin-1 ("oooseclave..." with
# three umlauts): charset-legal for a domain, case-folded by the
# device, and practically collision-proof against real entries. The
# device refuses to store the domain, so nothing can shadow it.
VERSION_DOMAIN = "\xf6\xf6\xf6seclave.version"
VERSION_MARKER = "\xf6\xf6\xf6seclave"

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

# Shown in the table where a field has not been revealed yet. It stands for a
# value the device holds but has not been asked for, which an empty cell would
# not distinguish from a field that is genuinely empty.
UNKNOWN_FIELD = "•••"

# Shown in place of revealed fields the user covered with the Hide fields
# button. The values stay in the row - hiding guards against onlookers, it
# forgets nothing - so copying or re-showing them costs no new device read.
HIDDEN_FIELD = "(hidden)"

# Reading groups one by one (pre-2.7, no GET_LABELGROUPIDX) is promptless only
# in "Allow all" access mode; in Normal and Ask all the device raises a
# confirmation per entry, which a human answers no faster than this. A single
# group read that takes longer is taken as proof the device is prompting, and
# the bulk load stops and points the user at the access-mode setting instead of
# marching through a confirmation per entry.
GROUP_PROMPT_SENSE_SECONDS = 1.0

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

# The freeform fields - username, password and a regular entry's optional -
# accept any byte, and two of them are worth having: the device types a stored
# tab as a Tab keypress and a stored newline as Enter, which is what fills a
# two-field login form or submits it. A Tk entry draws both as blank space, so
# the UI shows a marker glyph in their place and converts back before anything
# reaches the device.
#
# Neither marker is Latin-1 encodable, and the device stores only Latin-1, so a
# marker can never be mistaken for a character read back from a device: the
# substitution reverses without an escape scheme. That is also why there is no
# ASCII fallback for a font that lacks the glyph - a missing glyph draws a
# placeholder box, which still selects, copies and converts correctly, whereas
# an ASCII marker would corrupt any field holding that text literally.
MARK_TAB = "→"   # rightwards arrow
MARK_RET = "↵"   # downwards arrow with corner leftwards

# Carriage return has no marker on purpose. The device's keyboard tables map
# tab and newline to real keypresses but hold no entry for CR, so a stored CR
# types nothing while still spending one of the field's bytes.
MARKED_CONTROLS = (("\t", MARK_TAB), ("\n", MARK_RET))


def encode_marks(text):
    """Device text -> what the UI shows. Idempotent: text already carrying
    markers holds no control characters left to convert."""
    for control, mark in MARKED_CONTROLS:
        text = text.replace(control, mark)
    return text


def decode_marks(text):
    """What the UI shows -> device text. Idempotent, for the same reason."""
    for control, mark in MARKED_CONTROLS:
        text = text.replace(mark, control)
    return text


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
# Backup archive (offline). A backup is 501 slots of 256 bytes: 500 records
# and one header, each a 224-byte item plus a zero tail. An item's first 208
# bytes are AES-128-CTR ciphertext, MACed (CBC-MAC over IV then ciphertext,
# truncated to 10 bytes) with the item's index and a type cookie in plaintext
# behind it. The header (slot 500) carries the nonce every IV mixes in and
# the encrypted entry count. The two working keys derive from the 16-byte
# backup key the device shows as 32 hex digits under Backup -> Show key; the
# archive alone, without that key, reveals nothing. This matches the firmware
# byte for byte and is tested against an archive the firmware itself
# generated.
#
# AES-128 is spelled out below because this program is standard-library only,
# and the standard library has no AES. Byte-oriented and slow, but a full
# archive still opens in a couple of seconds, off the UI thread.
# ---------------------------------------------------------------------------

class BackupFileError(Exception):
    """The file is not a Seclave 2 backup archive."""


class BackupKeyError(Exception):
    """The archive does not authenticate under the given key: a wrong key, or
    a damaged file - a MAC mismatch cannot tell those apart."""


_AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16")
_AES_INV_SBOX = bytes(_AES_SBOX.index(i) for i in range(256))
_AES_RCON = b"\x01\x02\x04\x08\x10\x20\x40\x80\x1b\x36"

# ShiftRows moves within the flat 16-byte state (byte i is row i%4 of
# column i//4): out[i] = in[_AES_SHIFT[i]], and the inverse table undoes it.
_AES_SHIFT = (0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11)
_AES_INV_SHIFT = (0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3)


def _xtime(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def _gmul(a, b):
    """GF(2^8) multiply, for InvMixColumns (used only in key derivation)."""
    product = 0
    while b:
        if b & 1:
            product ^= a
        a = _xtime(a)
        b >>= 1
    return product


def aes_expand_key(key):
    """The 11 round keys of AES-128, as a list of 16-byte values."""
    words = [key[i:i + 4] for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = words[i - 1]
        if i % 4 == 0:
            temp = bytes(_AES_SBOX[b] for b in temp[1:] + temp[:1])
            temp = bytes([temp[0] ^ _AES_RCON[i // 4 - 1]]) + temp[1:]
        words.append(bytes(a ^ b for a, b in zip(words[i - 4], temp)))
    return [b"".join(words[4 * r:4 * r + 4]) for r in range(11)]


def aes_encrypt_block(round_keys, block):
    s = bytes(a ^ b for a, b in zip(block, round_keys[0]))
    for rnd in range(1, 11):
        s = bytes(_AES_SBOX[s[_AES_SHIFT[i]]] for i in range(16))
        if rnd < 10:
            mixed = bytearray(16)
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = s[c:c + 4]
                mixed[c] = _xtime(a0) ^ _xtime(a1) ^ a1 ^ a2 ^ a3
                mixed[c + 1] = a0 ^ _xtime(a1) ^ _xtime(a2) ^ a2 ^ a3
                mixed[c + 2] = a0 ^ a1 ^ _xtime(a2) ^ _xtime(a3) ^ a3
                mixed[c + 3] = _xtime(a0) ^ a0 ^ a1 ^ a2 ^ _xtime(a3)
            s = mixed
        s = bytes(a ^ b for a, b in zip(s, round_keys[rnd]))
    return s


def aes_decrypt_block(round_keys, block):
    s = bytes(a ^ b for a, b in zip(block, round_keys[10]))
    for rnd in range(9, -1, -1):
        s = bytes(_AES_INV_SBOX[s[_AES_INV_SHIFT[i]]] for i in range(16))
        s = bytes(a ^ b for a, b in zip(s, round_keys[rnd]))
        if rnd > 0:
            mixed = bytearray(16)
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = s[c:c + 4]
                mixed[c] = (_gmul(a0, 14) ^ _gmul(a1, 11) ^
                            _gmul(a2, 13) ^ _gmul(a3, 9))
                mixed[c + 1] = (_gmul(a0, 9) ^ _gmul(a1, 14) ^
                                _gmul(a2, 11) ^ _gmul(a3, 13))
                mixed[c + 2] = (_gmul(a0, 13) ^ _gmul(a1, 9) ^
                                _gmul(a2, 14) ^ _gmul(a3, 11))
                mixed[c + 3] = (_gmul(a0, 11) ^ _gmul(a1, 13) ^
                                _gmul(a2, 9) ^ _gmul(a3, 14))
            s = bytes(mixed)
    return s


def _aes_ctr(round_keys, counter, data):
    """CTR keystream XOR - encryption and decryption are the same operation.
    The counter increments big-endian across its full width, as the
    firmware's does."""
    out = bytearray(data)
    ctr = bytearray(counter)
    for off in range(0, len(out), 16):
        stream = aes_encrypt_block(round_keys, bytes(ctr))
        chunk = min(16, len(out) - off)
        for i in range(chunk):
            out[off + i] ^= stream[i]
        for i in range(15, -1, -1):
            ctr[i] = (ctr[i] + 1) & 0xFF
            if ctr[i]:
                break
    return bytes(out)


def _aes_cbc_mac(round_keys, chunks):
    """CBC-MAC starting from a zero block, over the chunks in order. Every
    chunk is a multiple of 16 - the layout guarantees it, as in the
    firmware."""
    mac = bytes(16)
    for data in chunks:
        for off in range(0, len(data), 16):
            mac = aes_encrypt_block(round_keys, bytes(
                a ^ b for a, b in zip(mac, data[off:off + 16])))
    return mac


# The firmware's key-derivation constants, 16 random bytes each. A working
# key is the AES *decryption* of a constant under the backup key, so holding
# a derived key does not yield the others.
_ENCKEY_CONSTANT = bytes.fromhex("4a18d9f57880ef1bbd9bd162a995efc8")
_MACKEY_CONSTANT = bytes.fromhex("6dfb51477ead4d3233b590630e3750a8")

# Plaintext slot-type cookies. The \xf2 family is a first-generation Seclave
# archive, which this file cannot decode (different record layout and
# crypto lineage) - it is recognized only to say so.
_PWDREC_COOKIE = b"\x08\xf3\x22\x00"
_BKPHDR_COOKIE = b"\x08\xf3\x23\x00"
_LEGACY_COOKIES = (b"\x08\xf2\x22\x00", b"\x08\xf2\x23\x00")

# Where things sit in a 224-byte item. Every item ends in its 10-byte MAC,
# index and cookie; the header keeps its encrypted part in the first block
# and its own MAC after the nonce.
_ITEM_MAC = slice(BACKUP_ENC_SIZE, BACKUP_ENC_SIZE + 10)
_ITEM_INDEX = slice(218, 220)
_ITEM_COOKIE = slice(220, 224)
_HDR_ENC = slice(0, 16)
_HDR_NONCE = slice(186, 202)
_HDR_MAC = slice(202, 212)

_WRONG_KEY = ("The backup key does not match this archive (or the file is "
              "damaged). Check the key against Backup -> Show key on the "
              "device that made the backup.")
_HEX_DIGITS = "0123456789ABCDEF"


def _derive_backup_keys(backup_key):
    """(encryption, MAC) round keys derived from the 16-byte backup key."""
    root = aes_expand_key(backup_key)
    return (aes_expand_key(aes_decrypt_block(root, _ENCKEY_CONSTANT)),
            aes_expand_key(aes_decrypt_block(root, _MACKEY_CONSTANT)))


def _backup_iv(nonce, index):
    """The per-item counter: the item's index as big-endian 16 bits at bytes
    12..13 of an otherwise zero block, XORed with the archive's nonce."""
    iv = bytearray(16)
    iv[12:14] = struct.pack(">H", index)
    return bytes(a ^ b for a, b in zip(iv, nonce))


def parse_backup_key(text):
    """The 32 hex digits of the backup key, as 16 bytes. Accepts the digits
    with or without the dash/space grouping the device and the dialog show,
    any case. None if it is not exactly 32 hex digits."""
    digits = "".join(ch for ch in text if ch not in " -")
    if len(digits) != 32:
        return None
    try:
        return bytes.fromhex(digits)
    except ValueError:
        return None


def format_backup_key(text):
    """Anything typed -> the display form: uppercase hex digits in blocks of
    8 separated by '-', everything else dropped. Idempotent."""
    digits = "".join(ch for ch in text.upper()
                     if ch in _HEX_DIGITS)[:32]
    return "-".join(digits[i:i + 8] for i in range(0, len(digits), 8))


def read_backup_archive(data, backup_key):
    """Decrypt and authenticate a backup archive. Returns the entries as
    dicts of label/group/username/password/optional, in the device's own
    (label-sorted) order. Raises BackupFileError for a file that is not a
    Seclave 2 archive, BackupKeyError for one that does not MAC under the
    key. Every slot is authenticated before anything is trusted, exactly as
    the device's restore does."""
    if len(data) != BACKUP_SLOT_SIZE * BACKUP_ITEMS:
        raise BackupFileError(
            f"Not a Seclave backup: the file is {len(data)} bytes; an "
            f"archive is always {BACKUP_SLOT_SIZE * BACKUP_ITEMS}.")

    header = data[MAX_ENTRIES * BACKUP_SLOT_SIZE:]
    cookie = header[_ITEM_COOKIE]
    if cookie in _LEGACY_COOKIES:
        raise BackupFileError(
            "This is a first-generation Seclave backup, which this program "
            "cannot decode. Restore it onto a Seclave with the device's "
            "Legacy restore instead.")
    if cookie != _BKPHDR_COOKIE or struct.unpack(
            "<H", header[_ITEM_INDEX])[0] != MAX_ENTRIES:
        raise BackupFileError("Not a Seclave backup: no backup header where "
                              "the archive keeps it.")

    nonce = header[_HDR_NONCE]
    enc_keys, mac_keys = _derive_backup_keys(backup_key)

    iv = _backup_iv(nonce, MAX_ENTRIES)
    mac = _aes_cbc_mac(mac_keys, (iv, header[_HDR_ENC]))
    if mac[:10] != header[_HDR_MAC]:
        raise BackupKeyError(_WRONG_KEY)
    declared = struct.unpack(
        "<H", _aes_ctr(enc_keys, iv, header[_HDR_ENC])[4:6])[0]

    entries = {}
    for index in range(MAX_ENTRIES):
        slot = data[index * BACKUP_SLOT_SIZE:(index + 1) * BACKUP_SLOT_SIZE]
        if any(slot[BACKUP_BLOB_SIZE:]):
            raise BackupFileError(f"Not a Seclave backup: slot {index} has "
                                  "data outside its item.")
        if slot[_ITEM_COOKIE] != _PWDREC_COOKIE:
            raise BackupFileError(f"Not a Seclave backup: slot {index} is not "
                                  "a record.")
        off = struct.unpack("<H", slot[_ITEM_INDEX])[0]
        if off >= MAX_ENTRIES or off in entries:
            raise BackupFileError("Damaged backup: record slots repeat or "
                                  "point outside the store.")
        # The index is plaintext, but not malleable: it decides the IV the
        # MAC is computed over, so a moved record fails to authenticate.
        iv = _backup_iv(nonce, off)
        mac = _aes_cbc_mac(mac_keys, (iv, slot[0:BACKUP_ENC_SIZE]))
        if mac[:10] != slot[_ITEM_MAC]:
            raise BackupKeyError(_WRONG_KEY)
        plain = _aes_ctr(enc_keys, iv, slot[0:BACKUP_ENC_SIZE])
        status = plain[16]
        if status == 0:
            entries[off] = None      # a free slot, present and authentic
            continue
        if status != 1:
            raise BackupFileError(f"Damaged backup: record {off} has an "
                                  "impossible status.")

        def field(start, end):
            return plain[start:end].split(b"\0", 1)[0].decode("latin-1")

        entries[off] = {"label": field(0, 16), "group": field(17, 25),
                        "username": field(25, 75), "password": field(75, 125),
                        "optional": field(125, 208)}

    found = [entries[off] for off in sorted(entries) if entries[off]]
    if len(found) != declared:
        raise BackupFileError("Damaged backup: the header promises "
                              f"{declared} entries, the records hold "
                              f"{len(found)}.")
    return found


def write_backup_archive(path, items):
    """Write streamed backup items as the archive the device itself presents
    over mass storage: each 224-byte item zero-padded into its 256-byte slot,
    byte-identical to SECLAVE.BKP - the layout the device's restore flow reads
    back. Written to a temporary file beside the target and renamed into
    place, so a failure part-way never leaves a truncated archive under the
    real name. Returns the byte count written."""
    data = b"".join(item.ljust(BACKUP_SLOT_SIZE, b"\x00") for item in items)
    fd, tmp = tempfile.mkstemp(prefix=".seclave-",
                               dir=os.path.dirname(os.path.abspath(path)))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return len(data)


# What every backup export carries, in column order. The password is
# deliberately included: exporting the plaintext is this feature's purpose,
# and the user was warned when the backup was opened.
EXPORT_FIELDS = ("label", "group", "username", "password", "optional")


def entries_to_json(entries):
    return json.dumps([{key: entry[key] for key in EXPORT_FIELDS}
                       for entry in entries],
                      ensure_ascii=False, indent=2) + "\n"


def entries_to_csv(entries):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(EXPORT_FIELDS)
    for entry in entries:
        writer.writerow([entry[key] for key in EXPORT_FIELDS])
    return out.getvalue()


def _yaml_quote(value):
    """Always double-quoted, so no value can be misread as a number, bool,
    anchor or comment; the escapes cover the control characters a stored
    tab/newline puts in a field."""
    escaped = []
    for ch in value:
        if ch in '"\\':
            escaped.append("\\" + ch)
        elif ch == "\t":
            escaped.append("\\t")
        elif ch == "\n":
            escaped.append("\\n")
        elif ch == "\r":
            escaped.append("\\r")
        elif ord(ch) < 0x20:
            escaped.append(f"\\x{ord(ch):02x}")
        else:
            escaped.append(ch)
    return '"' + "".join(escaped) + '"'


def entries_to_yaml(entries):
    """A block sequence of flat mappings. Hand-emitted (the standard library
    has no YAML), kept trivially simple: every scalar is a quoted string."""
    if not entries:
        return "[]\n"
    lines = []
    for entry in entries:
        prefix = "- "
        for key in EXPORT_FIELDS:
            lines.append(prefix + key + ": " + _yaml_quote(entry[key]))
            prefix = "  "
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Serial transport. CDC-ACM is a virtual UART, so configuration reduces to "raw
# mode" - baud is irrelevant. Each transport owns an mmap arena and reads one
# response at a time straight into it (never into an intermediate `bytes`). The
# shared interface is:
#   open(), write(bytes), begin_recv(), recv() -> memoryview, wipe(), wake(),
#   probe(), close().
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

    def probe(self):
        """Raise Disconnected if the port is gone. An unplug while no command
        is in flight fails no I/O on its own, so the worker probes between
        commands; nothing may go out on the wire here - any real frame could
        prompt for a confirmation on the device."""
        import termios
        try:
            termios.tcgetattr(self.fd)   # returns EIO/ENXIO once the tty died
        except termios.error:
            raise Disconnected
        if not os.path.exists(self.path):
            raise Disconnected

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

    def probe(self):
        # See PosixSerial.probe. ClearCommError is the same liveness check the
        # blocked-read loop uses: it fails once the port object is gone.
        import ctypes
        from ctypes import wintypes
        errors = wintypes.DWORD(0)
        if not self._k32.ClearCommError(self.handle, ctypes.byref(errors),
                                        None):
            debug("port gone (probe: ClearCommError error %d)",
                  ctypes.get_last_error())
            raise Disconnected

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


def parse_import_json(text):
    """Entries from a JSON import file: a list of objects with the same five
    fields the JSON export writes - label required, the rest optional and
    empty when absent. Returns (entries, problems); the problems are
    human-readable and nothing may be sent unless the list is empty, so a
    bad file is fixed as a whole instead of half-imported. The freeform
    fields take the marker glyphs too, converted to the control characters
    they stand for; unknown fields are refused rather than dropped - a typo
    like "usernmae" must not silently lose a value."""
    try:
        data = json.loads(text)
    except ValueError as err:
        return [], [f"Not JSON: {err}"]
    if not isinstance(data, list):
        return [], ["The file must be a JSON list of entries, as the JSON "
                    "export writes."]
    if len(data) > MAX_ENTRIES:
        return [], [f"The file holds {len(data)} entries; the device stores "
                    f"at most {MAX_ENTRIES}."]
    entries = []
    problems = []
    seen = {}
    for i, item in enumerate(data):
        where = f"entry {i + 1}"
        if not isinstance(item, dict):
            problems.append(f"{where}: not a JSON object.")
            continue
        if isinstance(item.get("label"), str) and item["label"]:
            where = f"entry {i + 1} ({item['label']})"
        good = True
        entry = {}
        for key in EXPORT_FIELDS:
            value = item.get(key, "")
            if not isinstance(value, str):
                problems.append(f"{where}: {key} must be a string.")
                good = False
                value = ""
            if key not in ("label", "group"):
                value = decode_marks(value)
            entry[key] = value
        for key in item:
            if key not in EXPORT_FIELDS:
                problems.append(f"{where}: unknown field {key!r}.")
                good = False
        for key, problem in (
                ("label", validate_restricted(entry["label"], MAX_LABEL,
                                              allow_empty=False)),
                ("group", validate_restricted(entry["group"], MAX_GROUP,
                                              allow_empty=True)),
                ("username", validate_freeform(entry["username"],
                                               MAX_USERNAME)),
                ("password", validate_freeform(entry["password"],
                                               MAX_PASSWORD)),
                ("optional", validate_freeform(entry["optional"],
                                               MAX_OPTIONAL))):
            if problem:
                problems.append(f"{where}: {key}: {problem}")
                good = False
        if not good:
            continue
        fold = latin1_fold(entry["label"])
        if fold in seen:
            problems.append(f"{where}: same label as entry {seen[fold]} - the "
                            "device holds one entry per label.")
            continue
        seen[fold] = i + 1
        entries.append(entry)
    return entries, problems


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

    def query_status(self):
        """The device's firmware version, used entries and total capacity,
        as three strs. Promptless in every access mode - none of it is a
        secret. Only safe on firmware that answered the version probe:
        older firmware treats an unknown command as a parse error and
        leaves slave mode."""
        payload = bytes([OP_QUERY_STATUS])
        try:
            status, spans, view = self._exchange(payload, 3)
            if status == ST_ABORT:
                raise Cancelled
            if status != ST_OK:
                raise DeviceError(status)
            return tuple(bytes(view[start:end]).decode("latin-1")
                         for start, end in spans)
        finally:
            self.transport.wipe()

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

    def list_label_groups(self):
        """(label, group) per entry - the same enumeration and the same
        single confirmation as list_labels, with the group riding along.
        Firmware 2.7+ only: older firmware treats the opcode as a parse
        error and drops out of slave mode, so gate on the version probe."""
        pairs = []
        index = 0
        while True:
            payload = bytes([OP_GET_LABELGROUPIDX]) + encode_int(index)
            try:
                status, spans, view = self._exchange(payload, 2)
                if status == ST_OUT_OF_INDEX:
                    return pairs
                if status == ST_ABORT:
                    raise Cancelled
                if status != ST_OK:
                    raise DeviceError(status)
                (ls, le), (gs, ge) = spans
                pairs.append((bytes(view[ls:le]).decode("latin-1"),
                              bytes(view[gs:ge]).decode("latin-1")))
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

    def stream_backup(self):
        """Yield the encrypted backup one 224-byte item at a time: the record
        slots and then the backup header, until the device answers
        OUT_OF_INDEX. The first item raises the device's "Export backup"
        confirmation; a confirm latches for the session and the rest stream
        without prompting. The items are opaque ciphertext under the backup
        key, so plain bytes are fine - no SecretBuffer needed."""
        index = 0
        while True:
            payload = bytes([OP_GET_BACKUP]) + encode_int(index)
            try:
                status, spans, view = self._exchange(payload, 1)
                if status == ST_OUT_OF_INDEX:
                    return
                if status == ST_ABORT:
                    raise Cancelled
                if status != ST_OK:
                    raise DeviceError(status)
                (start, end), = spans
                item = bytes(view[start:end])
            finally:
                self.transport.wipe()
            if len(item) != BACKUP_BLOB_SIZE:
                # Session-fatal by design: a wrong-size item means we are out
                # of step with the device, and every later slot would land at
                # the wrong offset of the archive.
                raise Disconnected
            yield item
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
        # this already; this guards any caller that bypasses it.
        if validate_restricted(domain, MAX_OPTIONAL, False):
            raise DeviceError(ST_BAD_DOMAIN)
        # Firmware 2.7 and later refuses this domain itself; earlier firmware
        # would store it, and a stored entry can shadow the version probe. A
        # crafted one even answers the probe like 2.7+ firmware would, and the
        # QUERY_STATUS that follows is an unknown command to the firmware that
        # let it be stored - a parse error, which drops it out of slave mode.
        if latin1_fold(domain) == latin1_fold(VERSION_DOMAIN):
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

    @staticmethod
    def _failure_reason(err):
        return ("was declined on the device" if isinstance(err, Cancelled)
                else "failed: %s" % err)

    @staticmethod
    def _entry_summary(data):
        """The tabled fields of an entry we just wrote, for the saved event."""
        return {name: data[name] for name in ("label",) + TABLE_FIELDS}

    def _edit_entry(self, data):
        """An edit never deletes first: whatever fails, the device holds the
        credential - old, new, or briefly both - at every step."""
        fields = {k: data[k] for k in
                  ("label", "group", "username", "password", "optional")}
        summary = self._entry_summary(data)
        if latin1_fold(data["old_label"]) != latin1_fold(fields["label"]):
            # A rename: the new label is free, so this is a plain add with
            # a definite answer. The old entry goes only once the new one
            # is on the device; a failed delete leaves a leftover to clean
            # up, never a lost credential.
            self.session.put_entry(**fields)
            try:
                self.session.del_entry(data["old_label"])
            except (Cancelled, DeviceError) as err:
                self.emit("saved", view="labels", action="edit",
                          old_label=data["old_label"],
                          old_remains=self._failure_reason(err), **summary)
            else:
                self.emit("saved", view="labels", action="edit",
                          old_label=data["old_label"], **summary)
            return
        # The label is unchanged, so the put lands on the entry itself and
        # the device asks the user whether to replace it. Firmware 2.7 and
        # later answers with the outcome: OK for replaced, a decline
        # otherwise. 2.6 and earlier answers "exists" while its replace
        # prompt is still open, and never reports the choice.
        try:
            self.session.put_entry(**fields)
        except DeviceError as err:
            if err.status != ST_LABEL_EXISTS:
                raise
        else:
            self.emit("saved", view="labels", action="edit",
                      old_label=data["old_label"], **summary)
            return
        if not data["changed"]:
            # Old and new records are identical; the prompt's outcome
            # cannot matter.
            self.emit("saved", view="labels", action="edit",
                      old_label=data["old_label"], **summary)
            return
        # Old firmware, outcome unknown. Fields the edit kept are the same
        # in both records and stay known; only the changed ones are not.
        # A changed group settles even those with one read: the get queues
        # behind the open prompt and returns the surviving record's group.
        if "group" in data["changed"]:
            try:
                group_now = self.session.get_group(fields["label"])
            except (Cancelled, DeviceError):
                group_now = None
            if group_now == fields["group"]:
                self.emit("saved", view="labels", action="edit",
                          old_label=data["old_label"], **summary)
                return
            if group_now == data["old_group"]:
                self.emit("declined", request="edit_entry")
                return
        self.emit("save_pending", view="labels", label=fields["label"],
                  changed=data["changed"])

    def _edit_wwwfill(self, data):
        if wwwfill_key(data["old_domain"], data["old_username"]) != \
                wwwfill_key(data["domain"], data["username"]):
            # A new identity - free per the duplicate check, so a plain
            # add; the old pair goes only after it succeeded.
            self.session.put_wwwfill(data["domain"], data["username"],
                                     data["password"])
            try:
                self.session.del_wwwfill(data["old_domain"],
                                         data["old_username"])
            except (Cancelled, DeviceError) as err:
                self.emit("saved", view="web",
                          old_remains=self._failure_reason(err),
                          old_pair="%s / %s" % (data["old_domain"],
                                                data["old_username"]))
            else:
                self.emit("saved", view="web")
            return
        # Same identity. In the default access mode the device replaces in
        # place and answers OK; in Ask all, firmware 2.6 and earlier
        # answers "exists" with its replace prompt still open. The stored
        # password is then old or new - nothing is cached, so the next
        # read simply shows the one that survived.
        try:
            self.session.put_wwwfill(data["domain"], data["username"],
                                     data["password"])
        except DeviceError as err:
            if err.status != ST_LABEL_EXISTS:
                raise
            self.emit("save_pending", view="web")
        else:
            self.emit("saved", view="web")

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

        elif name == "ping":
            # Idle liveness check from the UI's port poll. The probe raises
            # Disconnected when the port is gone, which run() turns into the
            # disconnected event; a live port answers with no event at all.
            if self.transport is not None:
                self.transport.probe()

        elif self.session is None:
            # The session dropped after the UI queued this request - a save
            # racing an unplug lands here. Answer with the disconnect it is;
            # a dead session would otherwise surface as an AttributeError.
            raise Disconnected

        elif name == "query_version":
            # Two stages (see VERSION_DOMAIN): the probe tells old and new
            # firmware apart with one promptless read that is safe
            # everywhere; only when the marker confirms 2.7+ does the
            # canonical QUERY_STATUS run for the version and store usage.
            # `definite` is False when the user declined the probe (Ask
            # all mode) - that proves nothing about the firmware.
            version = used = total = None
            definite = True
            try:
                user, pw, _ = self.session.get_wwwfill(VERSION_DOMAIN, 0)
            except Cancelled:
                definite = False
            except DeviceError as err:
                if err.status != ST_ENTRY_NOT_FOUND:
                    raise
            else:
                marker = user.text()
                user.clear()
                pw.clear()
                if marker.startswith(VERSION_MARKER):
                    version, used_text, total_text = \
                        self.session.query_status()
                    if used_text.isdigit() and total_text.isdigit():
                        used, total = int(used_text), int(total_text)
            self.emit("fw_info", version=version, used=used, total=total,
                      definite=definite)

        elif name == "load_labels":
            if req.data.get("with_groups"):
                pairs = self.session.list_label_groups()
                self.emit("loaded_labels", labels=[p[0] for p in pairs],
                          groups=dict(pairs))
            else:
                self.emit("loaded_labels", labels=self.session.list_labels())

        elif name == "load_labels_groups":
            # Pre-2.7 fallback for the group column: enumerate labels (one
            # confirmation), then read each group with GET_GROUP. That is quick
            # only in "Allow all" access mode; otherwise every read prompts on
            # the device. Time each one - a read past the sense threshold, or a
            # decline, means the device is prompting, so stop and let the UI
            # advise the mode change rather than storm the user with prompts.
            # The labels and the groups gathered so far are kept either way.
            labels = self.session.list_labels()
            groups = {}
            prompting = False
            for label in labels:
                started = time.monotonic()
                try:
                    groups[label] = self.session.get_group(label)
                except Cancelled:
                    prompting = True
                    break
                if time.monotonic() - started > GROUP_PROMPT_SENSE_SECONDS:
                    prompting = True
                    break
            self.emit("loaded_labels", labels=labels, groups=groups,
                      groups_prompting=prompting)

        elif name == "load_web":
            self.emit("loaded_web", web=self.session.list_wwwfill())

        elif name == "export_backup":
            # The whole encrypted archive, one item per round trip. Only a
            # complete stream reaches the disk: a decline, a stop or an
            # unplug part-way writes nothing.
            items = []
            for item in self.session.stream_backup():
                items.append(item)
                self.emit("backup_progress", done=len(items),
                          total=BACKUP_ITEMS)
            try:
                size = write_backup_archive(req.data["path"], items)
            except OSError as err:
                # A disk problem, not a device one: the session is fine, so
                # report it without dropping the connection.
                self.emit("error", status=None,
                          message=f"Could not write the backup file: {err}")
            else:
                self.emit("backup_saved", path=req.data["path"], size=size)

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

        elif name == "load_single":
            label = req.data["label"]
            group = self.session.get_group(label)
            self.emit("loaded_label_and_group", label=label, group=group)

        elif name == "fetch_wwwfill":
            # The table already shows the domain and username; only the
            # password needs fetching.
            user, pw, _ = self.session.get_wwwfill(req.data["domain"],
                                                   req.data["index"])
            user.clear()
            self.emit("wwwfill_fields", domain=req.data["domain"],
                      username=req.data["username"], password=pw,
                      purpose=req.data["purpose"])

        elif name == "import_json":
            # Every entry is sent, existing labels included - an import may
            # update stored entries, the password above all. A put onto a
            # label the device holds raises its Replace prompt (in Allow
            # all it replaces outright and answers OK): firmware 2.7+
            # answers the outcome - OK for replaced, a decline otherwise -
            # while 2.6 answers "exists" with its prompt still open and
            # never reports the choice; those land in `pending`.
            entries = req.data["entries"]
            added, declined, pending, unsent = [], [], [], []
            for i, entry in enumerate(entries):
                self.emit("import_progress", done=i + 1,
                          total=len(entries), label=entry["label"])
                try:
                    self.session.put_entry(**entry)
                except Cancelled:
                    # This entry was declined (or stopped); the next one
                    # is its own decision on the device.
                    declined.append(entry["label"])
                    continue
                except DeviceError as err:
                    if err.status == ST_LABEL_EXISTS:
                        pending.append(entry["label"])
                        continue
                    if err.status == ST_NO_SPACE:
                        # Full stops replacements too: the firmware checks
                        # space before it looks at the label.
                        unsent = [e["label"] for e in entries[i:]]
                        break
                    raise
                added.append(self._entry_summary(entry))
            self.emit("import_done", added=added, declined=declined,
                      pending=pending, unsent=unsent)

        elif name == "put_entry":
            # The saved events below carry what changed: the UI mirrors it
            # into the table instead of re-enumerating (see LabelRows). The
            # password is deliberately not among them - it is never tabled.
            self.session.put_entry(**req.data)
            self.emit("saved", view="labels", action="add",
                      **self._entry_summary(req.data))

        elif name == "put_wwwfill":
            self.session.put_wwwfill(**req.data)
            self.emit("saved", view="web")

        elif name == "edit_entry":
            self._edit_entry(req.data)

        elif name == "edit_wwwfill":
            self._edit_wwwfill(req.data)

        elif name == "del_entry":
            self.session.del_entry(req.data["label"])
            self.emit("saved", view="labels", action="delete",
                      label=req.data["label"])

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
# The label table's rows. Model only - no Tk - so it can be tested without a
# display.
# ---------------------------------------------------------------------------

class LabelRows:
    """A best-effort mirror of the entries stored on the device.

    Only a full enumeration knows which labels exist, and it costs a device
    confirmation the user may not want to give. Every other operation
    therefore updates the mirror in place instead of re-reading: loading a
    single entry, adding, editing and deleting each leave it agreeing with
    the device without asking it anything, so the table stays usable for a
    user who declines to enumerate again.

    Fields are held only once revealed - each one cost its own confirmation
    on the device - and a later enumeration keeps them: it replaces the set
    of labels, never the values already read out of them.

    A row can be marked hidden: the table then masks its revealed sensitive
    fields (username and optional - group stays shown), but the values stay
    in the row, so re-showing or copying them costs no new confirmation. The
    flag is display state only, and it survives an enumeration the same way
    the values do.

    Rows are kept in the device's own order, which is labels sorted under
    the case fold the device compares them with (see latin1_fold). Two
    labels differing only under that fold are one row here because they are
    one entry there.
    """

    def __init__(self):
        self._rows = {}        # fold key -> row
        # Whether the rows are known to be every entry on the device. A full
        # enumeration sets it; anything that can go stale behind our back
        # (a new session, a load about to be attempted) clears it.
        self.complete = False

    def __len__(self):
        return len(self._rows)

    @staticmethod
    def _blank(label):
        row = dict.fromkeys(TABLE_FIELDS)
        row["label"] = label
        row["hidden"] = False
        return row

    def rows(self):
        """Every row, in the device's label order."""
        return [self._rows[key] for key in sorted(self._rows)]

    def get(self, label):
        return self._rows.get(latin1_fold(label))

    def replace_all(self, labels):
        """Adopt a full enumeration. The device's list decides which labels
        exist; fields already revealed for the survivors are carried over."""
        rows = {}
        for label in labels:
            key = latin1_fold(label)
            row = self._rows.get(key) or self._blank(label)
            row["label"] = label      # the device's spelling wins
            rows[key] = row
        self._rows = rows
        self.complete = True

    def reveal(self, label, **fields):
        """Record fields now known for `label`, adding the row if it is not
        here yet. Known means read from the device under the user's
        confirmation, or just written there by us."""
        key = latin1_fold(label)
        row = self._rows.get(key)
        if row is None:
            row = self._blank(label)
            self._rows[key] = row
        for name, value in fields.items():
            if name not in TABLE_FIELDS:
                raise KeyError(f"not a label field: {name}")
            row[name] = value
        return row

    def forget(self, *fields):
        """Return the named fields to the not-read state in every row. Unlike
        hiding, this really forgets: the next look at one of these values
        costs a device confirmation again."""
        for name in fields:
            if name not in TABLE_FIELDS:
                raise KeyError(f"not a label field: {name}")
        for row in self._rows.values():
            for name in fields:
                row[name] = None

    def unread(self, label, *fields):
        """Return the named fields of one row to the not-read state - the
        row-level counterpart of forget, for when just this entry's values
        are no longer known to match the device."""
        row = self._rows.get(latin1_fold(label))
        if row is None:
            return
        for name in fields:
            if name not in TABLE_FIELDS:
                raise KeyError(f"not a label field: {name}")
            row[name] = None

    def toggle_hidden(self, label):
        """Flip whether the row's revealed fields are displayed or masked.
        The values stay in the row either way: hiding is for onlookers, it
        does not forget anything. Returns the new state."""
        row = self._rows[latin1_fold(label)]
        row["hidden"] = not row["hidden"]
        return row["hidden"]

    def remove(self, label):
        self._rows.pop(latin1_fold(label), None)

    def replace(self, old_label, label, **fields):
        """An edit: the old label's row makes way for the new one, which
        also covers a rename changing only the spelling."""
        self.remove(old_label)
        return self.reveal(label, **fields)


def next_sort(col, sort_col, sort_desc):
    """The (sort_col, sort_desc) after a click on column `col`: a first click
    sorts ascending, a second descending, a third returns to the default
    order - lexical by label under the device's own case fold, which both
    the device table and a backup's arrive in."""
    if sort_col != col:
        return col, False
    if not sort_desc:
        return col, True
    return None, False


# ---------------------------------------------------------------------------
# UI. Guarded so the protocol layer above can be imported and tested even where
# tkinter is not installed.
# ---------------------------------------------------------------------------

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
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
        # Row height is in pixels but the row font is in points, so a fixed
        # height clips the text on a scaled desktop. Size it from the font;
        # 24 is the floor, since Tk on macOS counts a point as a pixel and
        # would otherwise shrink the rows.
        linespace = tkfont.Font(root=root, font=base).metrics("linespace")
        rowheight = max(24, int(round(linespace * 4 / 3)))
        style.configure("Treeview", rowheight=rowheight,
                        fieldbackground=STYLE["bg"], background=STYLE["bg"],
                        foreground=STYLE["body"])
        style.configure("Treeview.Heading", font=bold,
                        background=STYLE["blue"], foreground=STYLE["white"])
        style.map("Treeview",
                  background=[("selected", STYLE["blue"])],
                  foreground=[("selected", STYLE["white"])])
        style.configure("Status.TLabel", background=STYLE["bg"],
                        foreground=STYLE["muted"])
        # The X11 message box wraps its text at 3 inches, which stacks anything
        # longer than a sentence into a tall narrow column. The option database
        # is the only way in; this entry outranks Tk's own because option_add
        # sets it at interactive priority. Windows and macOS use the native
        # dialog and ignore it.
        root.option_add("*Dialog.msg.wrapLength", "6i")
        return style

    def ask_path(ask, parent, **options):
        """Run a filedialog ask function (askopenfilename, asksaveasfilename)
        over `parent`, with the file list sized first; see fit_file_dialog."""
        if parent.tk.call("tk", "windowingsystem") == "x11":
            parent.after_idle(fit_file_dialog, parent)
        return ask(parent=parent, **options)

    def fit_file_dialog(parent):
        """Tk's own file dialog, the one X11 gets (Windows and macOS use the
        native one), lists files on a canvas fixed at 400x120 pixels: a few
        rows, and fewer still once the desktop scales text up. Size the list
        from its font. Queued by ask_path, this runs in the idle pass Tk makes
        before it measures and centres the dialog, so the dialog opens at the
        new size, centred. The dialog is kept and reused, so later opens find
        it sized already."""
        dialog = ("" if str(parent) == "." else str(parent)) + ".__tk_filedialog"
        canvas = dialog + ".contents.icons.cHull.canvas"
        if not int(parent.tk.call("winfo", "exists", canvas)):
            return
        line = tkfont.nametofont("TkIconFont", root=parent).metrics("linespace")
        width = min(40 * line, parent.winfo_screenwidth() * 3 // 4)
        height = min(18 * line, parent.winfo_screenheight() // 2)
        parent.tk.call(canvas, "configure", "-width", width, "-height", height)

    def draw_key_mark(canvas):
        """The key mark as simple vectors: brushed ring, blue lens, shaft with
        two notches. A small self-contained stand-in for a logo image."""
        canvas.create_oval(6, 6, 30, 30, outline=STYLE["muted"], width=3)
        canvas.create_oval(12, 12, 24, 24, fill=STYLE["blue"], outline="")
        canvas.create_oval(14, 14, 18, 18, fill=STYLE["white"], outline="")  # glint
        canvas.create_line(28, 18, 52, 18, fill=STYLE["muted"], width=3)
        canvas.create_line(44, 18, 44, 25, fill=STYLE["muted"], width=3)
        canvas.create_line(50, 18, 50, 24, fill=STYLE["muted"], width=3)

    def _toolbar_rule(parent):
        """A thin vertical rule that sets one cluster of toolbar buttons off
        from the next."""
        ttk.Separator(parent, orient="vertical").pack(
            side="left", fill="y", padx=8, pady=2)

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
                    text="Saving asks the device to replace this entry - "
                         "confirm it there.",
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
            # The buttons that sit beside a field, kept apart from the row
            # itself because they have to be hidden with it.
            self.extras = {}
            self._add_row("label", "Label", 1, MAX_LABEL)
            self._add_row("domain", "Domain", 1, MAX_OPTIONAL)
            self._add_row("group", "Group", 2, MAX_GROUP)
            self._add_row("username", "Username", 3, MAX_USERNAME, freeform=True)
            self._add_row("password", "Password", 4, MAX_PASSWORD, secret=True,
                          freeform=True)
            self._add_row("optional", "Optional", 5, MAX_OPTIONAL, freeform=True)

            btns = ttk.Frame(self)
            btns.grid(row=7, column=0, columnspan=3, sticky="e", **pad)
            ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right")
            self.save_btn = ttk.Button(btns, text="Save (device)",
                                       style="CTA.TButton", command=self._save)
            self.save_btn.pack(side="right", padx=6)

            self.error = ttk.Label(self, style="Muted.TLabel", text="")
            self.error.grid(row=6, column=0, columnspan=3, sticky="w", **pad)

        def _add_row(self, key, label, row, maxlen, secret=False,
                     freeform=False):
            lbl = ttk.Label(self, text=label)
            entry = ttk.Entry(self, textvariable=self.vars[key], width=40,
                              font=(self.mono, 11))
            counter = ttk.Label(self, style="Muted.TLabel", text="0/%d" % maxlen)
            lbl.grid(row=row, column=0, sticky="w", padx=8, pady=4)
            entry.grid(row=row, column=1, sticky="w", padx=8, pady=4)
            counter.grid(row=row, column=2, sticky="w", padx=8, pady=4)
            self.vars[key].trace_add("write", lambda *_: self._on_write(
                key, entry, counter, maxlen, freeform))
            self.rows[key] = (lbl, entry, counter)
            if not (secret or freeform):
                return
            extra = ttk.Frame(self)
            extra.grid(row=row, column=3, sticky="w")
            self.extras[key] = extra
            if freeform:
                # Only these three fields reach the device unvalidated; label,
                # group and domain are held to a charset that excludes both
                # control characters.
                for mark, name in ((MARK_TAB, "Tab"), (MARK_RET, "Enter")):
                    ttk.Button(extra, text=f"{mark} {name}",
                               command=lambda k=key, m=mark:
                               self._insert_mark(k, m)).pack(side="left")
            if secret:
                entry.configure(show="*")
                ttk.Checkbutton(extra, text="show", variable=self.show_pw,
                                command=lambda: entry.configure(
                                    show="" if self.show_pw.get() else "*")
                                ).pack(side="left")
                for n in (8, 12, 16, 20):
                    ttk.Button(extra, text=str(n), width=3,
                               command=lambda n=n: self.vars["password"].set(
                                   generate_password(n))).pack(side="left")

        def _insert_mark(self, key, mark):
            entry = self.rows[key][1]
            if entry.selection_present():
                entry.delete("sel.first", "sel.last")
            entry.insert(entry.index("insert"), mark)
            entry.focus_set()

        def _on_write(self, key, entry, counter, maxlen, freeform):
            if freeform:
                self._normalize(key)
            self._update_counter(key, entry, counter, maxlen)

        def _normalize(self, key):
            """Show a pasted control character as its marker, so what the field
            holds is always visible. A pasted CR becomes a newline: it is what
            the paste meant by Enter, and a CR of its own would sit there
            invisibly and type nothing."""
            raw = self.vars[key].get()
            fixed = encode_marks(raw.replace("\r\n", "\n").replace("\r", "\n"))
            if fixed != raw:
                # Re-entrant by one level: the write this triggers finds
                # nothing left to convert and stops.
                self.vars[key].set(fixed)

        def _update_counter(self, key, entry, counter, maxlen):
            # Red from the moment the field is full: one more character and the
            # device truncates silently (its put handlers copy MIN(sent, field
            # width)), so the warning has to come before the loss, not after.
            # Counted as the device will store it - a marker stands for one
            # byte, and encoding the marker itself would drop it from the tally.
            used = len(decode_marks(self.vars[key].get())
                       .encode("latin-1", "ignore"))
            colour = STYLE["red"] if used >= maxlen else STYLE["muted"]
            counter.configure(text="%d/%d" % (used, maxlen), foreground=colour)
            entry.configure(foreground=colour if used >= maxlen
                            else STYLE["body"])

        def _refresh_fields(self):
            web = self.is_web.get()
            shown = {"domain", "username", "password"} if web else \
                {"label", "group", "username", "password", "optional"}
            for key, (lbl, entry, counter) in self.rows.items():
                widgets = [lbl, entry, counter]
                if key in self.extras:
                    widgets.append(self.extras[key])
                for widget in widgets:
                    if key in shown:
                        widget.grid()
                    else:
                        widget.grid_remove()

        def _load_existing(self, existing):
            for key, value in existing.items():
                if key in self.vars and value is not None:
                    self.vars[key].set(encode_marks(value))

        def _field(self, key):
            """A field as the device will store it: the markers the UI shows
            converted back to the control characters they stand for. Validation
            and the saved values both work from this, never from the raw
            widget text - a marker is not Latin-1 and would fail the charset
            check that every field passes through."""
            return decode_marks(self.vars[key].get())

        def _save(self):
            if self.is_web.get():
                domain = normalize_domain(self._field("domain"))
                errors = [validate_restricted(domain, MAX_OPTIONAL, False),
                          validate_freeform(self._field("username"),
                                            MAX_USERNAME, allow_empty=False),
                          validate_freeform(self._field("password"),
                                            MAX_PASSWORD, allow_empty=False)]
                data = {"web": True, "domain": domain,
                        "username": self._field("username"),
                        "password": self._field("password")}
            else:
                errors = [validate_restricted(self._field("label"),
                                              MAX_LABEL, False),
                          validate_restricted(self._field("group"),
                                              MAX_GROUP, True),
                          validate_freeform(self._field("username"),
                                            MAX_USERNAME),
                          validate_freeform(self._field("password"),
                                            MAX_PASSWORD),
                          validate_freeform(self._field("optional"),
                                            MAX_OPTIONAL)]
                data = {"web": False}
                for key in ("label", "group", "username", "password", "optional"):
                    data[key] = self._field(key)
            problem = next((e for e in errors if e), None)
            if problem is None:
                # The app-level save can refuse too (the duplicate and
                # collision checks): it returns a message to show, or None
                # once the request is on its way to the device.
                problem = self.on_save(data, self.existing, self)
            if problem:
                self.error.configure(text=problem, foreground=STYLE["blue_hover"])
                return
            # Stay open until the device answers. An edit deletes the old
            # entry before adding the new one, so if the add is declined or
            # fails, what was typed here - the password above all - is the
            # only copy left; App closes the dialog on the saved event and
            # re-arms it on any failure.
            self.save_btn.configure(state="disabled")
            self.error.configure(text="Waiting for the device...",
                                 foreground=STYLE["muted"])

        def save_failed(self, message):
            """Re-arm Save after a failed attempt; the fields keep their
            values, so trying again is one click, not a retype."""
            self.save_btn.configure(state="normal")
            self.error.configure(text=message, foreground=STYLE["red"])

    class OpenBackupDialog(tk.Toplevel):
        """Choose a backup archive and enter its backup key. `on_open` gets
        (path, key_bytes) and returns None when the decrypt is under way, or
        a message to show. The dialog stays open until the App resolves it:
        closed on success, re-armed with the error on failure - so a
        mistyped key is a retype of the key, not of everything."""

        def __init__(self, parent, mono, on_open):
            super().__init__(parent)
            self.on_open = on_open
            self.mono = mono
            self.title("Open backup")
            self.configure(background=STYLE["bg"])
            self.transient(parent)
            self.resizable(False, False)
            pad = {"padx": 8, "pady": 4}

            ttk.Label(self, text="Backup file:").grid(row=0, column=0,
                                                      sticky="w", **pad)
            self.path_var = tk.StringVar()
            ttk.Entry(self, textvariable=self.path_var, width=44,
                      font=(mono, 11)).grid(row=0, column=1, sticky="w", **pad)
            ttk.Button(self, text="Browse...", command=self._browse).grid(
                row=0, column=2, sticky="w", **pad)

            ttk.Label(self, text="Backup key:").grid(row=1, column=0,
                                                     sticky="w", **pad)
            self.key_var = tk.StringVar()
            self.key_entry = ttk.Entry(self, textvariable=self.key_var,
                                       width=44, font=(mono, 11))
            self.key_entry.grid(row=1, column=1, sticky="w", **pad)
            self._format_pending = False
            self.key_var.trace_add("write", lambda *_: self._format_key())
            ttk.Label(self, style="Muted.TLabel",
                      text="The 32-character key from Backup -> Show key on "
                           "the device\nthat made the backup.").grid(
                row=2, column=1, columnspan=2, sticky="w", **pad)

            self.error = ttk.Label(self, style="Muted.TLabel", text="")
            self.error.grid(row=3, column=0, columnspan=3, sticky="w", **pad)

            btns = ttk.Frame(self)
            btns.grid(row=4, column=0, columnspan=3, sticky="e", **pad)
            ttk.Button(btns, text="Cancel", command=self.destroy).pack(
                side="right")
            self.open_btn = ttk.Button(btns, text="Open", style="CTA.TButton",
                                       command=self._open)
            self.open_btn.pack(side="right", padx=6)
            self.bind("<Return>", lambda e: self._open())
            self.bind("<Escape>", lambda e: self.destroy())
            self.grab_set()

        def _browse(self):
            path = ask_path(
                filedialog.askopenfilename, self,
                title="Open backup",
                filetypes=[("Seclave backup", "*.bkp *.BKP"),
                           ("All files", "*")])
            if path:
                self.path_var.set(path)
                self.key_entry.focus_set()

        def _format_key(self):
            # Deferred to idle: the trace fires mid-edit, and the Entry moves
            # its cursor after the trace returns, so regrouping here would
            # leave the cursor one short of an inserted dash.
            if not self._format_pending:
                self._format_pending = True
                self.after_idle(self._format_key_now)

        def _format_key_now(self):
            # Group as XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX; the device shows
            # the same digits with spaces, and a paste of either form lands
            # right. The set() below re-fires the trace, which schedules one
            # more pass that finds nothing left to fix.
            self._format_pending = False
            raw = self.key_var.get()
            fixed = format_backup_key(raw)
            if fixed == raw:
                return
            # Keep the cursor after the same number of digits it was after,
            # wherever the regrouping moved them.
            digits = sum(1 for ch in raw[:self.key_entry.index("insert")]
                         if ch.upper() in _HEX_DIGITS)
            self.key_var.set(fixed)
            cursor = 0
            while cursor < len(fixed) and digits > 0:
                if fixed[cursor] != "-":
                    digits -= 1
                cursor += 1
            self.key_entry.icursor(cursor)

        def _open(self):
            path = self.path_var.get().strip()
            key = parse_backup_key(self.key_var.get())
            if not path:
                return self._fail("Choose the backup file to open.")
            if key is None:
                return self._fail("The backup key is 32 hex digits; this "
                                  "is not.")
            problem = self.on_open(path, key)
            if problem:
                return self._fail(problem)
            self.open_btn.configure(state="disabled")
            self.error.configure(text="Decrypting...",
                                 foreground=STYLE["muted"])

        def _fail(self, message):
            self.error.configure(text=message, foreground=STYLE["red"])

        def open_failed(self, message):
            """Re-arm Open after a failed decrypt; the path and key stay."""
            self.open_btn.configure(state="normal")
            self._fail(message)

    class BackupViewer(tk.Toplevel):
        """Read-only table of a decrypted backup: label, group, username and
        optional in the clear, the password shown only on request for the
        selected row. Everything here lives in this window's memory alone -
        closing it is how the plaintext goes away. The export buttons write
        every entry, passwords included, to a plain file; the warning shown
        before the backup was opened covers both."""

        def __init__(self, parent, mono, path, entries):
            super().__init__(parent)
            self.mono = mono
            self.entries = entries
            self.sort_col = None
            self.sort_desc = False
            name = os.path.basename(path)
            self.export_stem = os.path.splitext(name)[0]
            self.title(f"Backup {name} - {len(entries)} entries "
                       "(decrypted, read-only)")
            self.configure(background=STYLE["bg"])

            row = ttk.Frame(self, padding=(10, 8))
            row.pack(fill="x")
            ttk.Label(row, text="Search:").pack(side="left")
            self.search_var = tk.StringVar()
            entry = ttk.Entry(row, textvariable=self.search_var, width=30,
                              font=(mono, 11))
            entry.pack(side="left", padx=6)
            entry.bind("<KeyRelease>", lambda e: self._render())
            for kind in ("yaml", "csv", "json"):
                ttk.Button(row, text=f"Export {kind.upper()}",
                           command=lambda k=kind: self._export(k)).pack(
                    side="right", padx=4)
            ttk.Label(row, text="Export all (with passwords):",
                      style="Muted.TLabel").pack(side="right", padx=(0, 4))

            table = ttk.Frame(self, padding=(10, 4))
            table.pack(fill="both", expand=True)
            cols = [("label", "Label", 180), ("group", "Group", 110),
                    ("username", "Username", 210), ("optional", "Optional", 210)]
            self.tree = ttk.Treeview(table, show="headings",
                                     selectmode="browse",
                                     columns=[c[0] for c in cols])
            for key, title, width in cols:
                self.tree.heading(key, text=title,
                                  command=lambda k=key: self._sort_by(k))
                self.tree.column(key, width=width, anchor="w")
            scroll = ttk.Scrollbar(table, orient="vertical",
                                   command=self.tree.yview)
            self.tree.configure(yscrollcommand=scroll.set)
            scroll.pack(side="right", fill="y")
            self.tree.pack(side="left", fill="both", expand=True)
            self.tree.bind("<<TreeviewSelect>>", lambda e: self._hide_password())
            self.tree.bind("<Double-1>", lambda e: self._show_entry())

            row = ttk.Frame(self, padding=(10, 4))
            row.pack(fill="x")
            ttk.Button(row, text="Show entry",
                       command=self._show_entry).pack(side="left", padx=4)
            self.pw_btn = ttk.Button(row, text="Show password",
                                     command=self._toggle_password)
            self.pw_btn.pack(side="left", padx=4)
            self.pw_var = tk.StringVar()
            self.pw_entry = ttk.Entry(row, textvariable=self.pw_var, width=40,
                                      font=(mono, 11), state="readonly")
            self.pw_entry.pack(side="left", padx=6)

            self.status = ttk.Label(self, text=f"{len(entries)} entries.",
                                    style="Status.TLabel", anchor="w",
                                    padding=(10, 4))
            self.status.pack(fill="x", side="bottom")
            self._render()
            self.bind("<Escape>", lambda e: self.destroy())

        def _render(self):
            needle = self.search_var.get().lower()
            visible = [e for e in self.entries
                       if not needle or any(needle in e[k].lower()
                                            for k in EXPORT_FIELDS
                                            if k != "password")]
            if self.sort_col:
                visible.sort(key=lambda e: latin1_fold(e[self.sort_col]),
                             reverse=self.sort_desc)
            self.tree.delete(*self.tree.get_children())
            self.row_by_iid = {}
            for i, entry in enumerate(visible):
                iid = str(i)
                self.tree.insert("", "end", iid=iid, values=tuple(
                    encode_marks(entry[k])
                    for k in ("label", "group", "username", "optional")))
                self.row_by_iid[iid] = entry
            self.status.configure(text=f"{len(visible)} of "
                                  f"{len(self.entries)} entries.")

        def _sort_by(self, col):
            self.sort_col, self.sort_desc = next_sort(
                col, self.sort_col, self.sort_desc)
            self._render()

        def _selected(self):
            sel = self.tree.selection()
            if not sel:
                self.status.configure(text="Select a row first.")
                return None
            return self.row_by_iid.get(sel[0])

        def _show_entry(self):
            entry = self._selected()
            if entry is None:
                return
            EntryViewer(self, self.mono, dict(entry, web=False))

        def _toggle_password(self):
            if self.pw_var.get():
                self._hide_password()
                return
            entry = self._selected()
            if entry is None:
                return
            self.pw_var.set(encode_marks(entry["password"]))
            self.pw_btn.configure(text="Hide password")

        def _hide_password(self):
            # Also fired by every selection change, so the shown password
            # always belongs to the selected row.
            self.pw_var.set("")
            self.pw_btn.configure(text="Show password")

        def _export(self, kind):
            serializer = {"json": entries_to_json, "csv": entries_to_csv,
                          "yaml": entries_to_yaml}[kind]
            path = ask_path(
                filedialog.asksaveasfilename, self,
                title=f"Export {kind.upper()}",
                initialfile=f"{self.export_stem}.{kind}",
                defaultextension="." + kind,
                filetypes=[(kind.upper(), "*." + kind), ("All files", "*")])
            if not path:
                return
            try:
                # newline="" so csv's own \r\n survives untranslated; the
                # other formats write plain \n either way.
                with open(path, "w", encoding="utf-8", newline="") as fh:
                    fh.write(serializer(self.entries))
            except OSError as err:
                messagebox.showwarning("Export failed", str(err), parent=self)
                return
            self.status.configure(
                text=f"Wrote {len(self.entries)} entries (passwords "
                     f"included) to {path}.")

    class EntryViewer(tk.Toplevel):
        """Read-only view of every field of one entry. The values are
        selectable; the password stays masked until "show" is ticked. Nothing
        here is cached - the window holds the only host-side copy, gone when
        it closes (or handed to the edit dialog by the Edit button, which
        reuses the just-fetched values instead of asking the device for
        every field again)."""

        def __init__(self, parent, mono, fields, on_edit=None):
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
                var = tk.StringVar(value=encode_marks(fields.get(key) or ""))
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
            self._on_edit = on_edit
            btns = ttk.Frame(self)
            btns.grid(row=len(rows), column=1, columnspan=2, sticky="e",
                      padx=8, pady=8)
            ttk.Button(btns, text="Close", command=self.destroy).pack(
                side="right")
            if on_edit is not None:
                ttk.Button(btns, text="Edit", command=self._edit).pack(
                    side="right", padx=6)
            self.bind("<Escape>", lambda e: self.destroy())
            self.grab_set()

        def _edit(self):
            on_edit = self._on_edit
            self.destroy()
            on_edit()

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
            # Labels keep a mirror that survives without re-enumerating (see
            # LabelRows). Web logins stay a plain list refreshed from the
            # device after every change, because the duplicate check needs it
            # to match the device exactly.
            self.labels = LabelRows()
            self.web_rows = []
            # Each view's entries are enumerated lazily and independently - one
            # device confirmation each - and only the first time this session.
            self.web_loaded = False
            self.sort_col = None
            self.sort_desc = False
            self.clip_value = None
            self.clip_after = None
            self.reveal_after = None
            self.pending_dialog = None   # a Save waiting for the device
            self.backup_dialog = None    # an Open backup awaiting decrypt
            # What the version oracle said. None = firmware 2.6 or earlier
            # (or not asked yet): the oracle itself arrived in 2.7, so its
            # absence is the version signal. _device_at_least() is the gate
            # for behavior that newer firmware does better.
            self.fw_version = None
            self.fw_used = None
            self.fw_total = None
            # Set once a device definitively answered "no oracle": that
            # firmware cannot answer the probe, so stop asking. Only an
            # app restart clears it.
            self.skip_version_probe = False

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

            ### Load row
            row = ttk.Frame(self, padding=(10, 4))
            row.pack(fill="x")
            
            self.load_btn = ttk.Button(row, text="Load view",
                                       style="CTA.TButton", command=self._load)
            self.load_btn.pack(side="left")
            # Only useful on a pre-2.7 device, where the label enumeration
            # carries no groups; shown by _refresh_group_button for those and
            # hidden otherwise (2.7+ loads groups with the labels already).
            self.load_groups_btn = ttk.Button(row, text="Load view + groups",
                                               command=self._load_groups)
            _toolbar_rule(row)

            self.load_single_btn = ttk.Button(row, text="Load single:",
                                               command=self._load_single)
            self.load_single_btn.pack(side="left", padx=(12, 0))
            self.load_single_var = tk.StringVar()
            self.single_entry = ttk.Entry(row, textvariable=self.load_single_var,
                                          width=20, font=(self.mono, 11))
            self.single_entry.pack(side="left", padx=6)
            self.single_entry.bind("<Return>", lambda e: self._load_single())

            _toolbar_rule(row)

            self.backup_btn = ttk.Button(row, text="Export backup",
                                         command=self._export_backup)
            self.backup_btn.pack(side="left", padx=4)
            # Opening works on a file alone - no device - so like hide_btn
            # it stays enabled while disconnected.
            self.open_backup_btn = ttk.Button(row, text="Open backup",
                                              command=self._open_backup)
            self.open_backup_btn.pack(side="left", padx=4)

            self.view_var = tk.StringVar(value="All labels")
            self.view_box = ttk.Combobox(
                row, textvariable=self.view_var, state="readonly", width=25,
                values=["All labels", "Web passwords (wwwfill)"])
            self.view_box.pack(side="right")
            self.view_box.bind("<<ComboboxSelected>>", lambda e: self._switch_view())
            ttk.Label(row, text="View:").pack(side="right", padx=(0, 2))

            ### Edit row
            row = ttk.Frame(self, padding=(10, 2))
            row.pack(fill="x")

            self.add_btn = ttk.Button(row, text="+ Add", command=self._add)
            self.add_btn.pack(side="left", padx=4)
            self.edit_btn = ttk.Button(row, text="Edit", command=self._edit)
            self.edit_btn.pack(side="left", padx=4)
            self.del_btn = ttk.Button(row, text="Delete", command=self._delete)
            self.del_btn.pack(side="left", padx=4)

            _toolbar_rule(row)

            self.import_btn = ttk.Button(row, text="Import JSON",
                                         command=self._import_json)
            self.import_btn.pack(side="left", padx=4)

            ### Copy row
            row = ttk.Frame(self, padding=(10, 2))
            row.pack(fill="x")

            self.copy_user_btn = ttk.Button(row, text="Copy username",
                                            command=lambda: self._copy("username"))
            self.copy_user_btn.pack(side="left", padx=4)
            self.copy_pw_btn = ttk.Button(row, text="Copy password",
                                          command=lambda: self._copy("password"))
            self.copy_pw_btn.pack(side="left", padx=4)
            self.copy_opt_btn = ttk.Button(row, text="Copy optional",
                                           command=self._copy_optional)
            self.copy_opt_btn.pack(side="left", padx=4)

            _toolbar_rule(row)

            self.hide_btn = ttk.Button(row, text="Hide fields",
                                       command=self._toggle_hidden)
            self.hide_btn.pack(side="left", padx=4)
            self.show_entry_btn = ttk.Button(row, text="Show entry",
                                             command=self._show_entry)            
            self.show_entry_btn.pack(side="left", padx=4)

            ### Search row
            row = ttk.Frame(self, padding=(10, 2))
            row.pack(fill="x")

            ttk.Label(row, text="Search:").pack(side="left", padx=(12, 0))
            self.search_var = tk.StringVar()
            entry = ttk.Entry(row, textvariable=self.search_var, width=40,
                              font=(self.mono, 11))
            entry.pack(side="left", padx=6)
            entry.bind("<KeyRelease>", lambda e: self._render())

            self.count_label = ttk.Label(row, text="0 entries",
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
            # The escape hatch for a wait the user will not finish: a
            # confirmable command blocks with nothing on the wire until
            # the device's prompt is answered. Interrupting is safe - the
            # transport flushes any late response before the next command
            # goes out.
            self.stop_btn = tk.Button(self.wait_bar, text="Stop waiting",
                                      command=self.worker.wake,
                                      font=(self.mono, 10))
            self.stop_btn.pack(side="right", padx=10, pady=2)
            self.stop_btn.pack_forget()   # shown only while waiting
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
            elif not self.busy:
                # While connected and idle nothing touches the port, so an
                # unplugged cable fails no I/O and would never reach the UI.
                # Skipped while busy: the in-flight command is already the
                # probe, and pings would pile up behind a long confirmation.
                self.worker.submit("ping")
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
            self._update_actions()
            self._refresh_group_button()
            # A device already found to predate the oracle cannot answer
            # the probe, so re-probing on every reconnect would only cost
            # an Ask-all confirmation for a known answer. A different or
            # upgraded device is re-detected after an app restart.
            if self.skip_version_probe:
                self._set_status(
                    "Connected - firmware 2.6 or earlier - click Load view")
                return
            # First thing on every connection: ask what device this is.
            # Instant and promptless in the Normal and Allow all access
            # modes; in Ask all the device may raise one confirmation,
            # which the wait bar explains.
            self._begin_wait("Checking the device's firmware version...")
            self.worker.submit("query_version")

        def _ev_fw_info(self, data):
            self._end_wait()
            self.skip_version_probe = data["definite"] and data["version"] is None
            self.fw_version = data["version"]
            self.fw_used = data["used"]
            self.fw_total = data["total"]
            if self.fw_version is None:
                fw = "firmware 2.6 or earlier"
            elif self.fw_used is not None:
                fw = ("firmware %s, %d of %d entries used"
                      % (self.fw_version, self.fw_used, self.fw_total))
            else:
                fw = "firmware %s" % self.fw_version
            self._set_status("Connected - %s - click Load view" % fw)
            self._refresh_group_button()

        def _ev_disconnected(self, data):
            self.connected = False
            self._end_wait()
            # A new session re-latches on the device, so the next enumeration will
            # prompt again - forget what was loaded. The device may also change
            # behind our back while we are away, so the label mirror is no
            # longer known to be complete.
            self.labels.complete = False
            self.web_loaded = False
            # Whatever reconnects may be a different device or firmware.
            self.fw_version = self.fw_used = self.fw_total = None
            # The trusted path just left the desk: the revealed sensitive
            # fields go back to not-read, while labels and groups stay to
            # keep the table navigable.
            self.labels.forget(*SENSITIVE_FIELDS)
            self._render()
            self._release_dialog("Device disconnected - reconnect, then "
                                 "Save again; the values are still here.")
            self.conn_label.configure(text="● disconnected",
                                      foreground=STYLE["muted"])
            self._refresh_group_button()
            self._set_status('Device disconnected - re-enter "Usb slave" on the '
                             "device to reconnect. Labels and groups stay; "
                             "other revealed fields were cleared.")
            self._update_actions()

        def _ev_loaded_labels(self, data):
            self._end_wait()
            # Fields revealed earlier survive this; only the set of labels is
            # replaced.
            self.labels.replace_all(data["labels"])
            # Firmware 2.7+ answers the group alongside each label - the
            # same enumeration and confirmation, so the group column fills
            # without a per-label read.
            for label, group in (data.get("groups") or {}).items():
                self.labels.reveal(label, group=group)
            self._set_status(f"Loaded {len(self.labels)} labels.")
            self._render()
            # The pre-2.7 group load stops the moment the device is seen to
            # prompt per entry; point the user at the access-mode setting so
            # the rest of the groups can load without a confirmation each.
            if data.get("groups_prompting"):
                self._warn_group_load_prompts()

        def _ev_loaded_label_and_group(self, data):
            # One entry, one confirmation: it joins the table without the full
            # enumeration a "Show all labels" prompt would cost. The mirror
            # stays incomplete - this says nothing about the other entries.
            self._end_wait()
            self.labels.reveal(data["label"], group=data["group"])
            self._set_status(f"Loaded {data['label']}.")
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
            if any(latin1_fold(row["domain"]) == latin1_fold(VERSION_DOMAIN)
                   for row in self.web_rows):
                # Only reachable on firmware that does not reserve the name -
                # 2.6 or earlier - and only if some other tool stored it. The
                # row stays listed rather than being hidden, so it can be
                # deleted from here.
                message = ("The device holds a web password under the name "
                           "reserved for version discovery. That is only "
                           "possible on firmware 2.6 or earlier, and it makes "
                           "version detection unreliable - delete that entry.")
                messagebox.showwarning("Seclave Companion", message)
                self._set_status(message)

        def _ev_backup_progress(self, data):
            # Only the wait text changes: the export is one long device
            # action, opened by _export_backup's _begin_wait and closed by
            # the saved (or declined/error) event.
            if self.busy:
                self.wait_text.configure(
                    text=f"Exporting backup - {data['done']} of "
                         f"{data['total']}...")

        def _ev_backup_saved(self, data):
            self._end_wait()
            self._set_status(f"Backup written to {data['path']} "
                             f"({data['size']} bytes).")
            messagebox.showinfo(
                "Export backup",
                f"Backup written to {data['path']} ({data['size']} bytes)."
                "\n\nRestoring it needs the backup key (Backup -> Show key "
                "on the device). Keep the file and the key in separate "
                "places - together they can reconstruct every password.")

        def _ev_import_progress(self, data):
            if self.busy:
                self.wait_text.configure(
                    text=f"Look at your Seclave - confirm {data['label']} "
                         f"({data['done']} of {data['total']}).")

        def _ev_import_done(self, data):
            self._end_wait()
            # The adds (and reported replaces) were ours, so the mirror
            # learns them like any other save - no re-enumeration, the
            # password never tabled.
            for summary in data["added"]:
                self.labels.reveal(summary["label"],
                                   **{k: summary[k] for k in TABLE_FIELDS})
            for label in data["pending"]:
                # Old firmware answered "exists" with its Replace prompt
                # open and will not report the choice: the stored entry is
                # old or imported, so the row's fields turn unread, the
                # way an in-place edit's do.
                self.labels.unread(label, *TABLE_FIELDS)
            self._render()
            total = sum(len(data[k]) for k in
                        ("added", "pending", "declined", "unsent"))
            lines = [f"Added or updated {len(data['added'])} of {total} "
                     "entries."]
            for names, what in (
                    (data["pending"], "met an existing label - answer "
                     "Replace on the device (the choice is not reported, "
                     "so their fields show as unread)"),
                    (data["declined"], "declined on the device"),
                    (data["unsent"], "not sent - the device is full")):
                if names:
                    shown = ", ".join(names[:5])
                    if len(names) > 5:
                        shown += f", ... ({len(names) - 5} more)"
                    lines.append(f"{len(names)} {what}: {shown}")
            self._set_status(lines[0])
            messagebox.showinfo("Import JSON", "\n".join(lines))

        def _ev_backup_opened(self, data):
            dialog, self.backup_dialog = self.backup_dialog, None
            if dialog is not None and dialog.winfo_exists():
                dialog.destroy()
            BackupViewer(self, self.mono, data["path"], data["entries"])
            self._set_status("Opened backup "
                             f"{os.path.basename(data['path'])} - "
                             f"{len(data['entries'])} entries (read-only).")

        def _ev_backup_open_failed(self, data):
            dialog, self.backup_dialog = self.backup_dialog, None
            if dialog is not None and dialog.winfo_exists():
                # Keep it pending: path and key stay for another try.
                self.backup_dialog = dialog
                dialog.open_failed(data["message"])
            else:
                messagebox.showwarning("Open backup", data["message"])
            self._set_status(data["message"])

        def _ev_secret(self, data):
            secret = data["secret"]
            self._copy_secret(secret)
            self._end_wait()
            self._set_status("Copied %s to clipboard - clears in %d s."
                             % (data["field"], CLIPBOARD_CLEAR_MS // 1000))

        def _ev_optional(self, data):
            # Optional is not a secret, so it also lands in the table - and
            # stays there, a later enumeration included.
            self._end_wait()
            self.labels.reveal(data["label"], optional=data["value"])
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
            # confirmations - reflect them in the table, where they stay.
            self.labels.reveal(data["label"], group=data["group"],
                               username=username, optional=data["optional"])
            self._render()
            fields = {"web": False, "label": data["label"],
                      "group": data["group"], "username": username,
                      "password": password, "optional": data["optional"],
                      "_old_label": data["label"]}
            self._show_fetched(fields, data["purpose"])

        def _ev_wwwfill_fields(self, data):
            self._end_wait()
            password = data["password"].text()
            data["password"].clear()
            fields = {"web": True, "domain": data["domain"],
                      "username": data["username"], "password": password,
                      "_old_domain": data["domain"],
                      "_old_username": data["username"]}
            self._show_fetched(fields, data["purpose"])

        def _show_fetched(self, fields, purpose):
            """Open the fetched entry for the purpose it was fetched for. The
            viewer's Edit button reuses the same values: every field was just
            read under the user's confirmations, so switching to edit must
            not cost a second round of them."""
            if purpose == "edit":
                EntryDialog(self, self.mono, self._on_dialog_save,
                            existing=fields)
            else:
                EntryViewer(self, self.mono, fields,
                            on_edit=lambda: EntryDialog(
                                self, self.mono, self._on_dialog_save,
                                existing=fields))

        def _ev_saved(self, data):
            self._end_wait()
            self._release_dialog()
            old_remains = data.get("old_remains")
            if data["view"] == "web":
                if old_remains:
                    message = ("Saved the new web password, but deleting "
                               "the old one (%s) %s - remove it from the "
                               "list when convenient."
                               % (data["old_pair"], old_remains))
                    messagebox.showwarning("Seclave Companion", message)
                    self._set_status(message)
                # Re-enumerate: the duplicate check reads web_rows as an exact
                # picture of the device. Within a session the first
                # enumeration confirmation is latched, so this costs no prompt.
                self.worker.submit("load_web")
                self._begin_wait("Refreshing web passwords...")
                return
            # Labels are mirrored instead of re-read. The change was ours, so
            # its effect on the device is known exactly, and a user who never
            # enumerated keeps working with the entries they have touched.
            action, label = data["action"], data["label"]
            if action == "delete":
                self.labels.remove(label)
                self._set_status(f"Deleted {label}.")
            else:
                fields = {name: data[name] for name in TABLE_FIELDS}
                if action == "edit" and not old_remains:
                    self.labels.replace(data["old_label"], label, **fields)
                else:
                    # A plain add, or a rename whose old entry is still on
                    # the device - its row stays until it really goes.
                    self.labels.reveal(label, **fields)
                verb = "Saved" if action == "edit" else "Added"
                if old_remains:
                    message = (f"{verb} {label}, but deleting the old entry "
                               f"{data['old_label']} {old_remains} - remove "
                               "it when convenient.")
                    messagebox.showwarning("Seclave Companion", message)
                    self._set_status(message)
                else:
                    self._set_status(f"{verb} {label}.")
            self._render()

        def _ev_save_pending(self, data):
            # Firmware 2.6 and earlier answered "exists" and is showing its
            # Replace prompt: the entry keeps its old values on a decline
            # and takes the new ones on a confirm, and the device never
            # says which. Nothing is lost either way, so the dialog closes;
            # what the edit changed is unread until it is read again.
            self._end_wait()
            self._release_dialog()
            if data["view"] == "labels":
                unread = [name for name in data["changed"]
                          if name in TABLE_FIELDS]
                if unread:
                    self.labels.unread(data["label"], *unread)
                    self._render()
                message = ("Answer Replace on the device: %s keeps its old "
                           "values on a decline. The choice is not "
                           "reported, so the changed fields show as unread."
                           % data["label"])
            else:
                message = ("Answer Replace on the device: the web password "
                           "keeps its old or new value. A later copy shows "
                           "the one that survived.")
            self._set_status(message)

        def _ev_declined(self, data):
            self._end_wait()
            self._release_dialog("Declined (or stopped) - nothing was "
                                 "changed by this step. The values are "
                                 "still here; Save to try again.")
            self._set_status("Declined on device.")

        def _ev_error(self, data):
            self._end_wait()
            if self.pending_dialog is not None:
                self._release_dialog(data["message"])
            else:
                messagebox.showwarning("Seclave Companion", data["message"])
            self._set_status(data["message"])

        def _ev_failed(self, data):
            # Status bar only: the port poll retries once a second, and a dialog
            # per retry would bury the window.
            self.connected = False
            self._end_wait()
            self._release_dialog("%s failed - %s. The values are still "
                                 "here; Save to try again."
                                 % (data["request"], data["message"]))
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
                self.labels.complete = False
                self._begin_wait("Loading - look at your Seclave and confirm "
                                 '"Show all labels".')
                self.worker.submit("load_labels",
                                   with_groups=self._device_at_least(2, 7))

        def _load_groups(self):
            # Pre-2.7 only (the button is hidden otherwise): load the labels and
            # then their groups one read at a time. Promptless in "Allow all"
            # access mode; in the other modes it stops at the first prompt and
            # the wait's end explains how to change the mode.
            if not self._require_connection():
                return
            self.labels.complete = False
            self._begin_wait('Loading labels - confirm "Show all labels" - '
                             "then the groups one by one.")
            self.worker.submit("load_labels_groups")

        def _warn_group_load_prompts(self):
            messagebox.showwarning(
                "Load view + groups",
                "This device asks you to confirm each group on the Seclave, so "
                "loading every group would prompt you once per entry.\n\n"
                "To load them all at once, set the device to \"Allow all\" "
                "access: on the Seclave, Admin -> Slave security -> Allow all, "
                "then click \"Load view + groups\" again.\n\n"
                "Careful: in \"Allow all\" mode any computer connected over USB "
                "can read every label, group, username, password and note "
                "without asking you to confirm on the device. Use it only on a "
                "computer you trust, and set Slave security back to \"Normal\" "
                "when you are done.")

        def _switch_view(self):
            self.view = "web" if self.view_var.get().startswith("Web") else "labels"
            self.sort_col = None
            self._configure_columns()
            self._refresh_group_button()
            self._render()
            # Enumerate this view the first time it is shown; if it is already
            # loaded this session the switch is purely local (no reconfirm).
            self._ensure_loaded()

        def _refresh_group_button(self):
            # The pre-2.7 group load belongs to the labels view of a device that
            # cannot fold groups into the enumeration. Shown only there, packed
            # right after the main Load button, hidden everywhere else.
            show = (self.connected and self.view == "labels"
                    and not self._device_at_least(2, 7))
            if show and not self.load_groups_btn.winfo_ismapped():
                self.load_groups_btn.pack(side="left", padx=4,
                                          after=self.load_btn)
            elif not show and self.load_groups_btn.winfo_ismapped():
                self.load_groups_btn.pack_forget()

        def _ensure_loaded(self):
            if self.busy or not self.connected:
                return
            if self.view == "web" and not self.web_loaded:
                self._begin_wait("Loading - look at your Seclave and confirm "
                                 '"Show all wwwfills".')
                self.worker.submit("load_web")
            elif self.view == "labels" and not self.labels.complete:
                self._begin_wait("Loading - look at your Seclave and confirm "
                                 '"Show all labels".')
                self.worker.submit("load_labels",
                                   with_groups=self._device_at_least(2, 7))

        def _sort_by(self, col):
            self.sort_col, self.sort_desc = next_sort(
                col, self.sort_col, self.sort_desc)
            self._render()

        def _render(self):
            rows = self.web_rows if self.view == "web" else self.labels.rows()
            needle = self.search_var.get().lower()
            keys = ("domain", "username") if self.view == "web" else \
                ("label",) + TABLE_FIELDS
            visible = [r for r in rows
                       if not needle or any(needle in str(r.get(k) or "").lower()
                                            for k in keys)]
            if self.sort_col:
                # Sort under the device's case fold, not str.lower(): the
                # fold is what orders the default view and what the device
                # itself compares with, and Python folds letters (E-acute,
                # sharp-s) the device keeps distinct.
                visible.sort(key=lambda r: latin1_fold(
                                 str(r.get(self.sort_col) or "")),
                             reverse=self.sort_desc)
            self.tree.delete(*self.tree.get_children())
            self.row_by_iid = {}
            for i, row in enumerate(visible):
                if self.view == "web":
                    values = (row["domain"], row["username"])
                else:
                    # None means "not revealed yet", which an empty string -
                    # a field the device really does hold empty - is not.
                    # A hidden row masks its revealed sensitive fields,
                    # without losing them.
                    values = (row["label"],) + tuple(
                        UNKNOWN_FIELD if row[name] is None else
                        HIDDEN_FIELD if row["hidden"] and
                        name in SENSITIVE_FIELDS else row[name]
                        for name in TABLE_FIELDS)
                iid = str(i)
                # A stored tab or newline would otherwise widen the cell with
                # blank space and read as an empty field.
                self.tree.insert("", "end", iid=iid,
                                 values=tuple(encode_marks(v) for v in values))
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
                return
            if field == "username" and row["username"] is not None:
                # Revealed earlier under its own confirmation - reuse it, as
                # _copy_optional does, instead of asking the device (and the
                # user) again. The password is never in the row, so a copy of
                # it is always a fresh, confirmed read.
                self._put_clipboard(row["username"])
                self._set_status("Copied username to clipboard - clears in "
                                 "%d s." % (CLIPBOARD_CLEAR_MS // 1000))
                return
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

        def _toggle_hidden(self):
            # Purely local - no device action - so unlike the other toolbar
            # buttons it stays available while disconnected or waiting:
            # exactly when a table left on screen needs covering.
            row = self._selected_row()
            if row is None:
                return
            if self.view == "web":
                self._set_status("Web rows show only what the enumeration "
                                 "listed - there is nothing to hide.")
                return
            if self.labels.toggle_hidden(row["label"]):
                self._set_status("Hid %s - the fields stay in memory, so "
                                 "showing or copying them again is free."
                                 % row["label"])
            else:
                self._set_status("Showing %s again." % row["label"])
            self._render()
            for iid, r in self.row_by_iid.items():
                if r is row:   # keep the row selected for the next toggle
                    self.tree.selection_set(iid)
                    break

        def _load_single(self):
            # One named entry into the table, for when the user will not spend
            # a "Show all labels" confirmation. Reading its group is what
            # proves to the device that the label exists.
            if not self._require_connection():
                return
            label = self.load_single_var.get().strip()
            if not label:
                self._set_status("Type the label of the entry to load.")
                return
            problem = validate_restricted(label, MAX_LABEL, allow_empty=False)
            if problem:
                self._set_status(f"Label: {problem}")
                return
            row = self.labels.get(label)
            if row is not None and row["group"] is not None:
                # Already read this session - the mirror keeps it, so a second
                # device confirmation would buy nothing.
                self._set_status(f"{row['label']} is already loaded.")
                self.load_single_var.set("")
                return
            self._begin_wait("Look at your Seclave - confirm showing the "
                             f"group for {label}.")
            self.worker.submit("load_single", label=label)
            self.load_single_var.set("")

        def _export_backup(self):
            # The device's encrypted backup, streamed over the serial
            # protocol into the same archive its mass-storage export
            # presents as SECLAVE.BKP. One confirmation on the device covers
            # the whole stream. The backup key never travels with it, so the
            # file alone reveals nothing - and restores nothing.
            if not self._require_connection():
                return
            path = ask_path(
                filedialog.asksaveasfilename, self,
                title="Export backup",
                initialfile=default_backup_filename(),
                defaultextension=".bkp",
                filetypes=[("Seclave backup", "*.bkp *.BKP"),
                           ("All files", "*")])
            if not path:
                return
            self._begin_wait('Look at your Seclave - confirm '
                             '"Export backup".')
            self.worker.submit("export_backup", path=path)

        def _import_json(self):
            # Bulk add from a file in the format the JSON export writes.
            # The whole file validates before anything is sent - a bad
            # file is fixed and retried, never half-imported.
            if not self._require_connection():
                return
            path = ask_path(
                filedialog.askopenfilename, self,
                title="Import JSON",
                filetypes=[("JSON", "*.json"), ("All files", "*")])
            if not path:
                return
            try:
                with open(path, encoding="utf-8") as fh:
                    text = fh.read()
            except (OSError, UnicodeDecodeError) as err:
                messagebox.showwarning("Import JSON",
                                       f"Could not read the file: {err}")
                return
            entries, problems = parse_import_json(text)
            if problems:
                shown = problems[:8]
                if len(problems) > len(shown):
                    shown.append(f"... and {len(problems) - len(shown)} more")
                messagebox.showwarning(
                    "Import JSON", "Nothing was imported - fix the file "
                    "first:\n\n" + "\n".join(shown))
                return
            if not entries:
                messagebox.showwarning("Import JSON",
                                       "The file holds no entries.")
                return
            if not messagebox.askokcancel(
                    "Import JSON",
                    f"Add {len(entries)} entries to the device?\n\nAn entry "
                    "whose label is already on the device raises its Replace "
                    "prompt: confirm on the device to update the stored "
                    "entry with the imported one, decline to keep what is "
                    "stored.\n\n"
                    "In the Normal and Ask all access modes the device asks "
                    "you to confirm each entry - for a large import, "
                    "Admin -> Slave security -> Allow all avoids the "
                    "prompts and replaces existing labels outright (set it "
                    "back afterwards)."):
                return
            self._begin_wait("Look at your Seclave - confirm each "
                             "imported entry.")
            self.worker.submit("import_json", entries=entries)

        def _open_backup(self):
            # Decrypting a backup on the computer is the one action here
            # that steps outside the device's trusted path: from the moment
            # it opens, every password in the archive is plaintext in this
            # process, on a machine the Seclave cannot vouch for. Said
            # before the file dialog, not after, so nothing is chosen yet
            # when the user thinks better of it.
            if not messagebox.askokcancel(
                    "Open backup",
                    "Opening a backup decrypts it on this computer.\n\n"
                    "Every username and password in it will be readable "
                    "here, without the per-read confirmations the Seclave "
                    "itself asks for - and can be exported to plain "
                    "files.\n\nOnly continue on a computer you trust with "
                    "all of the backup's passwords at once."):
                return
            self.backup_dialog = OpenBackupDialog(self, self.mono,
                                                  self._start_backup_decrypt)

        def _start_backup_decrypt(self, path, key):
            """Read and decrypt in a one-shot thread - the serial worker
            stays free, a backup opens with no device at all. Returns None
            once started, or a message for the dialog (its contract)."""
            def decrypt():
                try:
                    with open(path, "rb") as fh:
                        data = fh.read(BACKUP_SLOT_SIZE * BACKUP_ITEMS + 1)
                    entries = read_backup_archive(data, key)
                except OSError as err:
                    self.events.put(Event("backup_open_failed",
                                          message="Could not read the "
                                                  f"file: {err}"))
                except (BackupFileError, BackupKeyError) as err:
                    self.events.put(Event("backup_open_failed",
                                          message=str(err)))
                else:
                    self.events.put(Event("backup_opened", path=path,
                                          entries=entries))
            threading.Thread(target=decrypt, daemon=True).start()
            return None

        def _release_dialog(self, message=None):
            """Resolve a Save waiting in a dialog: close it on success, or
            re-arm it with `message` so the typed values - the password
            above all - survive the failure for another try."""
            dialog, self.pending_dialog = self.pending_dialog, None
            if dialog is None or not dialog.winfo_exists():
                return
            if message is None:
                dialog.destroy()
            else:
                dialog.save_failed(message)

        def _label_collision_problem(self, data, existing):
            # A put onto a label that already exists raises the device's
            # "Replace label?" prompt for that other entry, and firmware 2.6
            # and earlier never reports the choice - confirming it would
            # silently overwrite an entry the user did not mean to touch.
            # Refuse while the mirror knows the label is taken; like the
            # rest of the mirror this cannot see entries never loaded, so it
            # is a best-effort guard.
            row = self.labels.get(data["label"])
            if row is None:
                return None
            if existing and "_old_label" in existing and \
                    latin1_fold(existing["_old_label"]) == \
                    latin1_fold(data["label"]):
                return None   # an edit keeping its own label is no collision
            return ("An entry labeled %s already exists - edit that entry "
                    "instead, or delete it first." % row["label"])

        def _on_dialog_save(self, data, existing, dialog=None):
            """Submit a dialog Save to the worker. Returns None when the
            request was sent, or a message for the dialog to show - the entry
            is then not sent and the dialog stays open."""
            if not self.connected:
                # The dialog outlives a disconnect on purpose (the typed
                # values must survive), so its Save needs the connection
                # check the toolbar actions get from _require_connection.
                return ('Not connected - put your Seclave in the '
                        '"Usb slave" menu, then Save again.')
            if data["web"]:
                problem = (self._reserved_domain_problem(data) or
                           self._wwwfill_duplicate_problem(data, existing))
            else:
                problem = self._label_collision_problem(data, existing)
            if problem:
                return problem
            self.pending_dialog = dialog
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
                    # The worker needs to know what the edit changed: on old
                    # firmware an in-place replace does not report whether it
                    # happened, and only the changed fields become unknown.
                    changed = [k for k in
                               ("group", "username", "password", "optional")
                               if fields[k] != existing.get(k)]
                    self.worker.submit("edit_entry",
                                       old_label=existing["_old_label"],
                                       old_group=existing.get("group"),
                                       changed=changed, **fields)
                else:
                    self.worker.submit("put_entry", **fields)
            return None

        def _reserved_domain_problem(self, data):
            # Version discovery reads this name (see VERSION_DOMAIN), so an
            # entry stored under it would shadow the probe on firmware that
            # does not reserve the name itself. The domain arriving here is
            # already normalized by the dialog; both sides are folded because
            # the device treats the cased forms as the same name.
            if latin1_fold(data["domain"]) == latin1_fold(VERSION_DOMAIN):
                return ("This name is reserved for the device's version "
                        "discovery and cannot hold a web password.")
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
                    # Overwrite, don't just disown: clipboard_clear() alone
                    # leaves this app owning an X11 selection it has nothing
                    # to answer for, and some terminals (Alacritty) hang
                    # their paste waiting on it. A single space is served
                    # instantly and pastes as good as nothing - and the
                    # secret is gone from the clipboard either way.
                    self.clipboard_clear()
                    self.clipboard_append(" ")
            except tk.TclError:
                pass
            self.clip_value = None

        # ---- shared state helpers ----

        def _device_at_least(self, major, minor):
            """Whether the connected device's firmware is at or past a
            version - the gate for choosing behavior per firmware. Unknown
            or pre-oracle firmware counts as oldest."""
            if self.fw_version is None:
                return False
            parts = self.fw_version.split(".")
            try:
                return (int(parts[0]), int(parts[1])) >= (major, minor)
            except (ValueError, IndexError):
                return False

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
            self.stop_btn.pack(side="right", padx=10, pady=2)
            self._update_actions()

        def _end_wait(self):
            self.busy = False
            self.wait_bar.configure(background=STYLE["bg"])
            self.wait_dot.configure(text="", background=STYLE["bg"])
            self.wait_text.configure(text="", background=STYLE["bg"])
            self.stop_btn.pack_forget()
            self._update_actions()

        def _set_status(self, text):
            self.status.configure(text=text)

        def _update_actions(self):
            live = "normal" if (self.connected and not self.busy) else "disabled"
            for btn in (self.load_btn, self.load_groups_btn, self.add_btn,
                        self.edit_btn, self.show_entry_btn, self.del_btn,
                        self.copy_user_btn, self.copy_pw_btn, self.copy_opt_btn,
                        self.load_single_btn, self.backup_btn,
                        self.import_btn):
                btn.configure(state=live)
            # hide_btn is absent on purpose: hiding touches no device and is
            # wanted most exactly when the device is gone and the loaded rows
            # are left showing.

        def _show_help(self):
            messagebox.showinfo(
                "About Seclave Companion",
                "Seclave Companion %s\n"
                "Copyright (c) 2026 Seclave AB\n\n"
                "MIT licensed, and provided without warranty of any kind. The "
                "full licence text ships with the program, in the LICENSE "
                "file.\n\n"
                "Seclave is a trademark of Seclave AB."
                % (VERSION))

        def _on_close(self):
            self._clear_clipboard()
            self.worker.submit("quit")
            self.worker.wake()
            self.destroy()


def disable_core_dumps():
    """Set the core dump size limit to zero, where the platform has one.

    A core dump is a copy of exactly what the wiping above exists to control,
    and the kernel writes it at the moment of a crash - no `finally` gets to
    run first, so nothing else in this file can prevent it. Zeroing the limit
    is what makes the arena and SecretBuffer wiping worth doing: it closes the
    one path by which secret bytes reach the disk.

    POSIX only. Windows crash dumps are configured machine-wide through Windows
    Error Reporting, so there is nothing for a program to set there.
    """
    try:
        import resource
    except ImportError:
        return
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (OSError, ValueError) as err:
        # Not fatal: the app runs on with whatever limit it inherited, which is
        # the pre-existing behavior. Trace it so --debug can show it happened.
        debug("could not disable core dumps: %s", err)


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
    disable_core_dumps()
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

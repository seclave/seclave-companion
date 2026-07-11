#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 Seclave AB
"""Dev-only fake Seclave, speaking the USB-slave protocol over a pseudo-terminal.

NOT part of the shipped program. It lets us drive seclave_companion.py and the
protocol tests without real hardware. Run it directly to get a port path:

    python3 dev/stub_device.py

it prints e.g. "/dev/pts/7"; then in another terminal:

    python3 seclave_companion.py --port /dev/pts/7

Options: --delay SECONDS simulates the confirmation pause before every reply;
--abort makes every confirmable command return ABORT (declined). The in-memory
store is seeded with a few entries so the table has something to show.
"""

import os
import sys
import time
import argparse
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import seclave_companion as sc


class FakeDevice:
    def __init__(self, delay=0.0, always_abort=False):
        self.delay = delay
        self.always_abort = always_abort
        # Regular entries: label -> dict(group, username, password, optional).
        self.entries = {}
        # Web logins: list of dict(domain, username, password).
        self.web = []
        self.op_counts = {}   # opcode -> times handled, for tests
        self._seed()

    def _seed(self):
        self.entries = {
            "gmail": dict(group="personal", username="alice@example.com",
                          password="hunter2", optional="notes"),
            "github": dict(group="work", username="alice",
                           password="octocat!", optional="2fa on"),
            "aws-root": dict(group="work", username="root",
                             password="s3cr3t-root", optional="prod account"),
        }
        self.web = [
            dict(domain="github.com", username="alice", password="webpass-a"),
            dict(domain="github.com", username="bob", password="webpass-b"),
            dict(domain="news.example.co.uk", username="reader",
                 password="webpass-c"),
        ]

    # ---- framing helpers ----

    def _read_frame(self, fd):
        """Read one host->device frame (2-byte LE length + payload)."""
        header = self._read_exact(fd, 2)
        if header is None:
            return None
        length = header[0] | (header[1] << 8)
        if length == 0 or length > sc.MAX_FRAME_PAYLOAD:
            # The real device drops to keyboard mode; we just end the session.
            return None
        return self._read_exact(fd, length)

    def _read_exact(self, fd, n):
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = os.read(fd, n - len(buf))
            except OSError:
                return None
            if not chunk:
                return None
            buf += chunk
        return bytes(buf)

    def _confirm_pause(self):
        if self.delay:
            time.sleep(self.delay)

    # ---- dispatch ----

    def handle(self, payload):
        """Return the raw (unframed) response bytes for one request payload."""
        opcode = payload[0]
        body = payload[1:]
        self.op_counts[opcode] = self.op_counts.get(opcode, 0) + 1
        if opcode == sc.OP_GET_LABELIDX:
            self._confirm_pause()
            index, _ = sc.decode_int(body, 0)
            labels = sorted(self.entries) + [self._web_label(w) for w in self.web]
            if index >= len(labels):
                return bytes([sc.ST_OUT_OF_INDEX])
            return bytes([sc.ST_OK]) + sc.encode_field(sc.latin1(labels[index]))

        if opcode == sc.OP_GET_WWWFILLIDX:
            self._confirm_pause()
            index, _ = sc.decode_int(body, 0)
            if index >= len(self.web):
                return bytes([sc.ST_OUT_OF_INDEX])
            entry = self.web[index]
            return (bytes([sc.ST_OK]) + sc.encode_field(sc.latin1(entry["domain"]))
                    + sc.encode_field(sc.latin1(entry["username"])))

        if opcode in (sc.OP_GET_GROUP, sc.OP_GET_USERNAME, sc.OP_GET_PASSWORD,
                      sc.OP_GET_OPTIONAL):
            if self.always_abort:
                return bytes([sc.ST_ABORT])
            self._confirm_pause()
            (start, end), _ = sc.decode_field_span(body, 0)
            label = body[start:end].decode("latin-1")
            entry = self.entries.get(label) or self._web_entry_by_label(label)
            if entry is None:
                return bytes([sc.ST_ENTRY_NOT_FOUND])
            field = {sc.OP_GET_GROUP: "group", sc.OP_GET_USERNAME: "username",
                     sc.OP_GET_PASSWORD: "password",
                     sc.OP_GET_OPTIONAL: "optional"}[opcode]
            return bytes([sc.ST_OK]) + sc.encode_field(sc.latin1(entry[field]))

        if opcode == sc.OP_GET_WWWFILL:
            (start, end), off = sc.decode_field_span(body, 0)
            domain = body[start:end].decode("latin-1")
            index, _ = sc.decode_int(body, off)
            matches = [w for w in self.web if w["domain"] == domain]
            if index >= len(matches):
                return bytes([sc.ST_ENTRY_NOT_FOUND])
            entry = matches[index]
            status = sc.ST_MORE_LABELS if index + 1 < len(matches) else sc.ST_OK
            return (bytes([status]) + sc.encode_field(sc.latin1(entry["username"]))
                    + sc.encode_field(sc.latin1(entry["password"])))

        if opcode == sc.OP_PUT_ENTRY:
            self._confirm_pause()
            fields, _ = self._read_fields(body, 5)
            label, group, username, password, optional = fields
            if label in self.entries:
                return bytes([sc.ST_LABEL_EXISTS])
            self.entries[label] = dict(group=group, username=username,
                                       password=password, optional=optional)
            return bytes([sc.ST_OK])

        if opcode == sc.OP_PUT_WWWFILL:
            fields, _ = self._read_fields(body, 3)
            domain, username, password = fields
            for w in self.web:
                if w["domain"] == domain and w["username"] == username:
                    w["password"] = password
                    return bytes([sc.ST_OK])
            self.web.append(dict(domain=domain, username=username,
                                 password=password))
            return bytes([sc.ST_OK])

        if opcode == sc.OP_DEL_ENTRY:
            self._confirm_pause()
            (start, end), _ = sc.decode_field_span(body, 0)
            label = body[start:end].decode("latin-1")
            if label in self.entries:
                del self.entries[label]
                return bytes([sc.ST_OK])
            return bytes([sc.ST_ENTRY_NOT_FOUND])

        if opcode == sc.OP_DEL_WWWFILL:
            self._confirm_pause()
            fields, _ = self._read_fields(body, 2)
            domain, username = fields
            for w in list(self.web):
                if w["domain"] == domain and w["username"] == username:
                    self.web.remove(w)
                    return bytes([sc.ST_OK])
            return bytes([sc.ST_ENTRY_NOT_FOUND])

        return bytes([sc.ST_PARSE_ERROR])

    def _read_fields(self, body, count):
        values = []
        off = 0
        for _ in range(count):
            (start, end), off = sc.decode_field_span(body, off)
            values.append(body[start:end].decode("latin-1"))
        return values, off

    def _web_label(self, entry):
        # A web login is stored as a regular entry with an auto-generated label:
        # the first 13 characters of the domain plus a short unique suffix.
        return entry["domain"][:13] + "abc"

    def _web_entry_by_label(self, label):
        for w in self.web:
            fields = dict(group=sc.WWWFILL_GROUP, username=w["username"],
                          password=w["password"], optional=w["domain"])
            if self._web_label(w) == label:
                return fields
        return None

    # ---- serving ----

    def serve(self, fd):
        while True:
            payload = self._read_frame(fd)
            if payload is None:
                return
            try:
                response = self.handle(payload)
            except Exception:
                response = bytes([sc.ST_PARSE_ERROR])
            os.write(fd, response)


def start_pty(device):
    """Open a pty, serve `device` on the master in a thread, return (path, thread)."""
    master, slave = os.openpty()
    path = os.ttyname(slave)
    thread = threading.Thread(target=device.serve, args=(master,), daemon=True)
    thread.start()
    return path, thread, slave


def main():
    parser = argparse.ArgumentParser(description="Fake Seclave (dev only)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="seconds to pause before each reply (fake confirm)")
    parser.add_argument("--abort", action="store_true",
                        help="decline every confirmable command")
    args = parser.parse_args()
    device = FakeDevice(delay=args.delay, always_abort=args.abort)
    path, thread, _slave = start_pty(device)
    print(path, flush=True)
    thread.join()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 Seclave AB
"""End-to-end tests for the Seclave Companion protocol layer, driven against the
PTY stub device. Run: python3 dev/test_protocol.py

These exercise the shipped file's codec, DeviceSession and transport over a real
pseudo-terminal - the same path used against hardware, minus the joystick.
"""

import os
import sys
import time
import queue
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))   # the shipped file
sys.path.insert(0, HERE)                     # the stub

import seclave_companion as sc
import stub_device


def connect(device):
    path, _thread, _slave = stub_device.start_pty(device)
    transport = sc.PosixSerial(path)
    transport.open()
    return sc.DeviceSession(transport), transport


class CodecTests(unittest.TestCase):
    def test_int_roundtrip(self):
        for value in (0, 1, 5, 253, 254, 255, 256, 1000, 65535):
            buf = sc.encode_int(value)
            decoded, off = sc.decode_int(buf, 0)
            self.assertEqual(decoded, value)
            self.assertEqual(off, len(buf))

    def test_int_wire_shapes(self):
        # Escape-form encodings: 255 -> ff 01 ff, 0x6543 -> ff 02 43 65.
        self.assertEqual(sc.encode_int(255), b"\xff\x01\xff")
        self.assertEqual(sc.encode_int(0x6543), b"\xff\x02\x43\x65")

    def test_field_roundtrip(self):
        raw = b"hello"
        buf = sc.encode_field(raw)
        (start, end), off = sc.decode_field_span(buf, 0)
        self.assertEqual(buf[start:end], raw)
        self.assertEqual(off, len(buf))

    def test_frame_known_bytes(self):
        # GET_LABELIDX for index 0 frames to 02 00 06 00.
        self.assertEqual(sc.build_frame(bytes([sc.OP_GET_LABELIDX]) +
                                        sc.encode_int(0)),
                         bytes.fromhex("02000600"))

    def test_frame_bounds(self):
        with self.assertRaises(ValueError):
            sc.build_frame(b"")
        with self.assertRaises(ValueError):
            sc.build_frame(b"x" * 229)

    def test_partial_response_needs_more(self):
        # A length prefix promising 5 bytes but only 2 present -> not yet parseable.
        self.assertIsNone(sc.parse_response(bytearray([sc.ST_OK, 5, 1, 2]), 1))


class EnumerationTests(unittest.TestCase):
    def setUp(self):
        self.session, self.transport = connect(stub_device.FakeDevice())

    def tearDown(self):
        self.transport.close()

    def test_list_labels(self):
        labels = self.session.list_labels()
        self.assertIn("gmail", labels)
        self.assertIn("github", labels)
        self.assertIn("aws-root", labels)
        # wwwfill entries also surface in the label enumeration.
        self.assertTrue(any(l.startswith("github.com") for l in labels))

    def test_list_wwwfill(self):
        rows = self.session.list_wwwfill()
        self.assertEqual(rows[0], ("github.com", "alice"))
        self.assertEqual(rows[1], ("github.com", "bob"))
        self.assertEqual(rows[2][0], "news.example.co.uk")

    def test_list_label_groups_matches_the_label_walk(self):
        pairs = self.session.list_label_groups()
        self.assertEqual([p[0] for p in pairs], self.session.list_labels())
        groups = dict(pairs)
        self.assertEqual(groups["gmail"], "personal")
        # wwwfill entries surface under their reserved group.
        web_label = next(l for l in groups if l.startswith("github.com"))
        self.assertEqual(groups[web_label], "wwwfill")

    def test_per_label_groups_match_op14(self):
        # The pre-2.7 fallback reads groups one at a time with GET_GROUP; the
        # mapping it builds must match what op 14 returns in one enumeration.
        labels = self.session.list_labels()
        by_label = {label: self.session.get_group(label) for label in labels}
        self.assertEqual(by_label, dict(self.session.list_label_groups()))

    def test_enumerations_are_independent(self):
        # Listing labels must not touch the wwwfill enumeration, and vice versa -
        # each is its own single device confirmation.
        device = stub_device.FakeDevice()
        session, transport = connect(device)
        try:
            session.list_labels()
            self.assertGreater(device.op_counts.get(sc.OP_GET_LABELIDX, 0), 0)
            self.assertEqual(device.op_counts.get(sc.OP_GET_WWWFILLIDX, 0), 0)
            session.list_wwwfill()
            self.assertGreater(device.op_counts.get(sc.OP_GET_WWWFILLIDX, 0), 0)
        finally:
            transport.close()


class FieldTests(unittest.TestCase):
    def setUp(self):
        self.session, self.transport = connect(stub_device.FakeDevice())

    def tearDown(self):
        self.transport.close()

    def test_get_group(self):
        self.assertEqual(self.session.get_group("github"), "work")

    def test_get_secret_fields(self):
        self.assertEqual(self.session.get_username("gmail").text(),
                         "alice@example.com")
        self.assertEqual(self.session.get_password("gmail").text(), "hunter2")

    def test_get_optional_is_plain_text(self):
        # Optional is not secret-classified; it comes back as a plain string.
        value = self.session.get_optional("aws-root")
        self.assertEqual(value, "prod account")
        self.assertNotIsInstance(value, sc.SecretBuffer)

    def test_secret_buffer_clears(self):
        secret = self.session.get_password("github")
        self.assertEqual(secret.text(), "octocat!")
        secret.clear()
        self.assertEqual(secret.text(), "\x00" * len("octocat!"))

    def test_arena_zeroed_after_secret(self):
        # A completed secret fetch leaves the receive arena all zeros.
        secret = self.session.get_password("gmail")
        self.assertEqual(secret.text(), "hunter2")
        self.assertEqual(set(self.session.transport.arena.snapshot()), {0})

    def test_arena_zeroed_on_disconnect(self):
        # Bytes left mid-response are wiped when the transport closes.
        arena = self.session.transport.arena
        arena._map[:8] = b"leftover"
        arena.fill = 8
        self.session.transport.close()
        self.assertEqual(set(arena.snapshot()), {0})

    def test_unknown_label(self):
        with self.assertRaises(sc.DeviceError) as ctx:
            self.session.get_group("nope")
        self.assertEqual(ctx.exception.status, sc.ST_ENTRY_NOT_FOUND)


class WwwfillTests(unittest.TestCase):
    def setUp(self):
        self.session, self.transport = connect(stub_device.FakeDevice())

    def tearDown(self):
        self.transport.close()

    def test_more_labels_iteration(self):
        # github.com has two logins: index 0 -> MORE_LABELS, index 1 -> OK.
        user0, pw0, more0 = self.session.get_wwwfill("github.com", 0)
        self.assertEqual(user0.text(), "alice")
        self.assertEqual(pw0.text(), "webpass-a")
        self.assertTrue(more0)
        user1, pw1, more1 = self.session.get_wwwfill("github.com", 1)
        self.assertEqual(user1.text(), "bob")
        self.assertFalse(more1)

    def test_single_login(self):
        user, pw, more = self.session.get_wwwfill("news.example.co.uk", 0)
        self.assertEqual(user.text(), "reader")
        self.assertFalse(more)


class MutationTests(unittest.TestCase):
    def setUp(self):
        self.session, self.transport = connect(stub_device.FakeDevice())

    def tearDown(self):
        self.transport.close()

    def test_put_then_delete_entry(self):
        self.session.put_entry("newlabel", "grp", "user", "pass", "opt")
        self.assertIn("newlabel", self.session.list_labels())
        self.assertEqual(self.session.get_password("newlabel").text(), "pass")
        self.session.del_entry("newlabel")
        self.assertNotIn("newlabel", self.session.list_labels())

    def test_put_existing_label_reports_exists(self):
        with self.assertRaises(sc.DeviceError) as ctx:
            self.session.put_entry("gmail", "g", "u", "p", "o")
        self.assertEqual(ctx.exception.status, sc.ST_LABEL_EXISTS)

    def test_edit_via_delete_then_put(self):
        self.session.del_entry("github")
        self.session.put_entry("github", "work", "alice2", "newpw", "note")
        self.assertEqual(self.session.get_username("github").text(), "alice2")

    def test_put_then_delete_wwwfill(self):
        self.session.put_wwwfill("shop.example.com", "buyer", "wpw")
        rows = self.session.list_wwwfill()
        self.assertIn(("shop.example.com", "buyer"), rows)
        self.session.del_wwwfill("shop.example.com", "buyer")
        self.assertNotIn(("shop.example.com", "buyer"),
                         self.session.list_wwwfill())

    def test_put_wwwfill_guard_blocks_bad_domain(self):
        # The transport-layer domain guard: a domain outside the device charset
        # (embedded NUL being the dangerous case) must never reach the wire,
        # even from callers that bypass the dialog validation.
        device = stub_device.FakeDevice()
        session, transport = connect(device)
        try:
            for domain in ("evil\x00.com", "has space.com", ""):
                with self.assertRaises(sc.DeviceError) as ctx:
                    session.put_wwwfill(domain, "user", "pw")
                self.assertEqual(ctx.exception.status, sc.ST_BAD_DOMAIN)
            self.assertEqual(device.op_counts.get(sc.OP_PUT_WWWFILL, 0), 0)
        finally:
            transport.close()


class BackupTests(unittest.TestCase):
    """GET_BACKUP streams the encrypted archive; the export writes it in the
    SECLAVE.BKP slot layout the device's restore flow reads back."""

    def setUp(self):
        self.device = stub_device.FakeDevice()
        self.session, self.transport = connect(self.device)

    def tearDown(self):
        self.transport.close()

    def test_stream_is_501_items_of_224_bytes(self):
        items = list(self.session.stream_backup())
        self.assertEqual(len(items), sc.BACKUP_ITEMS)
        self.assertTrue(all(len(item) == sc.BACKUP_BLOB_SIZE
                            for item in items))
        self.assertEqual(items[0], self.device.backup_blob(0))
        self.assertEqual(items[-1], self.device.backup_blob(sc.MAX_ENTRIES))
        # The stream ends by reading past the header, never short of it.
        self.assertEqual(self.device.op_counts[sc.OP_GET_BACKUP],
                         sc.BACKUP_ITEMS + 1)

    def test_arena_zeroed_after_stream(self):
        list(self.session.stream_backup())
        self.assertEqual(set(self.session.transport.arena.snapshot()), {0})

    def test_archive_matches_the_mass_storage_layout(self):
        items = list(self.session.stream_backup())
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "seclave.bkp")
            size = sc.write_backup_archive(path, items)
            with open(path, "rb") as fh:
                data = fh.read()
            leftovers = [n for n in os.listdir(tmp) if n != "seclave.bkp"]
        self.assertEqual(leftovers, [])   # the temp file was renamed away
        self.assertEqual(size, len(data))
        # SECLAVE.BKP is 501 slots of 256 bytes = 128256; each slot is the
        # 224-byte wire item and then zero padding.
        self.assertEqual(len(data), sc.BACKUP_SLOT_SIZE * sc.BACKUP_ITEMS)
        for i, item in enumerate(items):
            slot = data[i * sc.BACKUP_SLOT_SIZE:(i + 1) * sc.BACKUP_SLOT_SIZE]
            self.assertEqual(slot[:sc.BACKUP_BLOB_SIZE], item)
            self.assertEqual(slot[sc.BACKUP_BLOB_SIZE:],
                             b"\x00" * (sc.BACKUP_SLOT_SIZE
                                        - sc.BACKUP_BLOB_SIZE))

    def test_decline_raises_cancelled(self):
        session, transport = connect(stub_device.FakeDevice(always_abort=True))
        try:
            with self.assertRaises(sc.Cancelled):
                list(session.stream_backup())
        finally:
            transport.close()


class BackupWorkerTests(unittest.TestCase):
    """The export_backup request end to end: progress events while streaming,
    the file on disk, and a disk failure reported without dropping the
    session."""

    def _drive(self, path):
        session, transport = connect(stub_device.FakeDevice())
        out = queue.Queue()
        worker = sc.Worker(out)
        worker.transport = transport
        worker.session = session
        worker.start()
        try:
            worker.submit("export_backup", path=path)
            events = []
            while True:
                event = out.get(timeout=10)
                events.append(event)
                if event.name != "backup_progress":
                    return events
        finally:
            worker.submit("quit")
            worker.join(timeout=5)

    def test_export_writes_the_file_and_reports_progress(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "seclave.bkp")
            events = self._drive(path)
            self.assertEqual(events[-1].name, "backup_saved")
            self.assertEqual(events[-1].data["path"], path)
            self.assertEqual(os.path.getsize(path), events[-1].data["size"])
            self.assertEqual(os.path.getsize(path),
                             sc.BACKUP_SLOT_SIZE * sc.BACKUP_ITEMS)
        progress = [e for e in events if e.name == "backup_progress"]
        self.assertEqual(len(progress), sc.BACKUP_ITEMS)
        self.assertEqual(progress[-1].data,
                         {"done": sc.BACKUP_ITEMS, "total": sc.BACKUP_ITEMS})

    def test_unwritable_path_reports_error_not_disconnect(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "no_such_dir", "seclave.bkp")
            events = self._drive(path)
        self.assertEqual(events[-1].name, "error")
        self.assertIn("Could not write the backup file", events[-1].data["message"])


class AbortTests(unittest.TestCase):
    def test_decline_raises_cancelled(self):
        session, transport = connect(stub_device.FakeDevice(always_abort=True))
        try:
            with self.assertRaises(sc.Cancelled):
                session.get_password("gmail")
        finally:
            transport.close()


class ValidationTests(unittest.TestCase):
    def test_overlength_rejected(self):
        self.assertIsNotNone(sc.validate_restricted("x" * 17, sc.MAX_LABEL, False))
        self.assertIsNotNone(sc.validate_freeform("y" * 51, sc.MAX_USERNAME))

    def test_valid_inputs_pass(self):
        self.assertIsNone(sc.validate_restricted("aws-root_1", sc.MAX_LABEL, False))
        self.assertIsNone(sc.validate_freeform("s3cr3t!", sc.MAX_PASSWORD))

    def test_bad_charset_rejected(self):
        self.assertIsNotNone(sc.validate_restricted("has space", sc.MAX_LABEL, False))
        self.assertIsNotNone(sc.validate_restricted("a@b", sc.MAX_LABEL, False))

    def test_domain_normalization(self):
        self.assertEqual(sc.normalize_domain("https://github.com:443/login"),
                         "github.com")

    def test_non_latin1_rejected(self):
        self.assertIsNotNone(sc.validate_freeform("emoji \U0001f600",
                                                  sc.MAX_PASSWORD))
        # The restricted validator must reject (not crash on) non-Latin-1 too.
        self.assertIsNotNone(sc.validate_restricted("caf\U0001f600",
                                                    sc.MAX_LABEL, False))


class WwwfillDedupTests(unittest.TestCase):
    """The client-side duplicate refusal that safeguards affected firmware: the
    uniqueness key is (device-case-folded domain, case-SENSITIVE username),
    matching the device exactly."""

    PAIRS = [("github.com", "alice"), ("github.com", "bob"),
             ("news.example.co.uk", "reader")]

    def test_duplicate_add_refused(self):
        self.assertIsNotNone(sc.wwwfill_duplicate_error(
            self.PAIRS, "github.com", "alice"))

    def test_domain_matches_case_insensitively(self):
        self.assertIsNotNone(sc.wwwfill_duplicate_error(
            self.PAIRS, "GitHub.COM", "alice"))

    def test_username_matches_case_sensitively(self):
        self.assertIsNone(sc.wwwfill_duplicate_error(
            self.PAIRS, "github.com", "Alice"))

    def test_new_pair_allowed(self):
        self.assertIsNone(sc.wwwfill_duplicate_error(
            self.PAIRS, "example.org", "alice"))

    def test_edit_to_collision_refused(self):
        # Editing (news.example.co.uk, reader) into an identity that another
        # row already owns must be refused.
        self.assertIsNotNone(sc.wwwfill_duplicate_error(
            self.PAIRS, "github.com", "alice",
            skip=("news.example.co.uk", "reader")))

    def test_unchanged_edit_allowed(self):
        # An edit that keeps its identity must not collide with itself.
        self.assertIsNone(sc.wwwfill_duplicate_error(
            self.PAIRS, "github.com", "alice", skip=("github.com", "alice")))

    def test_domain_case_only_edit_allowed(self):
        # Changing only the domain's case keeps the same device key.
        self.assertIsNone(sc.wwwfill_duplicate_error(
            self.PAIRS, "GITHUB.com", "alice", skip=("github.com", "alice")))

    def test_edit_on_already_duplicated_store_refused(self):
        # If the device already holds the pair twice (the pre-lock state),
        # even an unchanged edit is the lock-up trigger - refuse it.
        pairs = self.PAIRS + [("GitHub.com", "alice")]
        self.assertIsNotNone(sc.wwwfill_duplicate_error(
            pairs, "github.com", "alice", skip=("github.com", "alice")))

    def test_load_scan_finds_existing_duplicate(self):
        pairs = self.PAIRS + [("GitHub.com", "alice")]
        self.assertEqual(sc.find_wwwfill_duplicates(pairs),
                         [("github.com", "alice")])
        self.assertEqual(sc.find_wwwfill_duplicates(self.PAIRS), [])

    def test_fold_matches_firmware_table(self):
        # The domain folds with the device's own table: ASCII A-Z plus
        # exactly the six two-case letters Ä Å Æ Ö Ø Ü.
        self.assertEqual(sc.latin1_fold("GitHub.COM"), b"github.com")
        self.assertEqual(sc.latin1_fold("ÄÅÆÖØÜ"), "äåæöøü".encode("latin-1"))
        # ...and the pairs fold in the dedup path too, not just in isolation.
        self.assertIsNotNone(sc.wwwfill_duplicate_error(
            [("örn.se", "u")], "ÖRN.se", "u"))
        self.assertEqual(sc.wwwfill_key("BLÅBÆR-grød.DK", "u"),
                         sc.wwwfill_key("blåbær-grød.dk", "u"))

    def test_fold_leaves_caseless_bytes_alone(self):
        # ß has no case pair on the device: "straße.de" and "strasse.de" are
        # two different domains there, although str.casefold() equates them
        # (ß -> "ss"). Both are dialog-legal, so this must not false-refuse.
        self.assertIsNone(sc.wwwfill_duplicate_error(
            [("straße.de", "u")], "strasse.de", "u"))
        self.assertIsNotNone(sc.wwwfill_duplicate_error(
            [("straße.de", "u")], "STRAßE.DE", "u"))
        # É is outside the firmware's fold table, so it compares exact,
        # although str.lower() would fold it to é.
        self.assertNotEqual(sc.latin1_fold("É"), sc.latin1_fold("é"))

    def test_gate_off_disables_refusal(self):
        # Once a device is confirmed on post-fix firmware the refusal can be
        # relaxed by flipping ENFORCE_WWWFILL_DEDUP - nothing else to change.
        previous = sc.ENFORCE_WWWFILL_DEDUP
        sc.ENFORCE_WWWFILL_DEDUP = False
        try:
            self.assertIsNone(sc.wwwfill_duplicate_error(
                self.PAIRS, "github.com", "alice"))
        finally:
            sc.ENFORCE_WWWFILL_DEDUP = previous


class GroupFallbackWorkerTests(unittest.TestCase):
    """The pre-2.7 group load lives in the Worker: enumerate labels, read each
    group, and report whether the device began prompting per entry."""

    def _drive(self, session, transport):
        out = queue.Queue()
        worker = sc.Worker(out)
        worker.transport = transport
        worker.session = session
        worker.start()
        try:
            worker.submit("load_labels_groups")
            return out.get(timeout=5)
        finally:
            worker.submit("quit")
            worker.join(timeout=5)

    def test_promptless_fills_every_group(self):
        device = stub_device.FakeDevice()
        session, transport = connect(device)
        event = self._drive(session, transport)
        self.assertEqual(event.name, "loaded_labels")
        self.assertFalse(event.data["groups_prompting"])
        groups = event.data["groups"]
        self.assertEqual(set(groups), set(event.data["labels"]))
        self.assertEqual(groups["gmail"], "personal")
        # A pre-2.7 load never sends op 14; the groups come from GET_GROUP.
        self.assertEqual(device.op_counts.get(sc.OP_GET_LABELGROUPIDX, 0), 0)
        self.assertGreater(device.op_counts.get(sc.OP_GET_GROUP, 0), 0)

    def test_slow_group_read_is_sensed_as_prompting(self):
        device = stub_device.FakeDevice()
        session, transport = connect(device)
        expected_labels = session.list_labels()
        # A group read past the sense threshold means the device is asking the
        # user to confirm each one: the load stops at the first and flags it,
        # instead of walking every entry behind a prompt.
        original = session.get_group
        saved = sc.GROUP_PROMPT_SENSE_SECONDS
        sc.GROUP_PROMPT_SENSE_SECONDS = 0.05

        def slow(label):
            time.sleep(0.1)
            return original(label)

        session.get_group = slow
        try:
            event = self._drive(session, transport)
        finally:
            sc.GROUP_PROMPT_SENSE_SECONDS = saved
        self.assertTrue(event.data["groups_prompting"])
        self.assertLessEqual(len(event.data["groups"]), 1)
        # The labels still all loaded - only the group walk was cut short.
        self.assertEqual(event.data["labels"], expected_labels)


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 Seclave AB
"""Tests for the JSON import: the file parser/validator, and the worker's
put-per-entry flow against the PTY stub device.
Run: python3 dev/test_import.py
"""

import os
import sys
import json
import queue
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))   # the shipped file
sys.path.insert(0, HERE)                     # the stub

import seclave_companion as sc
import stub_device


def entry(label, **fields):
    made = {"label": label, "group": "", "username": "", "password": "",
            "optional": ""}
    made.update(fields)
    return made


class ParseTests(unittest.TestCase):
    def test_round_trips_the_json_export(self):
        # What the export writes, the import reads back identically -
        # control characters included.
        exported = [entry("plain", group="g", username="u", password="p",
                          optional="o"),
                    entry("tricky", username="tab\there",
                          password='q"uo\\te', optional="line\nbreak")]
        entries, problems = sc.parse_import_json(sc.entries_to_json(exported))
        self.assertEqual(problems, [])
        self.assertEqual(entries, exported)

    def test_missing_fields_default_empty(self):
        entries, problems = sc.parse_import_json('[{"label": "only"}]')
        self.assertEqual(problems, [])
        self.assertEqual(entries, [entry("only")])

    def test_label_is_required(self):
        for text in ('[{}]', '[{"label": ""}]'):
            entries, problems = sc.parse_import_json(text)
            self.assertEqual(entries, [], text)
            self.assertTrue(problems, text)

    def test_marker_glyphs_become_their_controls(self):
        text = json.dumps([{"label": "marked",
                            "password": "pw" + sc.MARK_TAB + sc.MARK_RET}])
        entries, problems = sc.parse_import_json(text)
        self.assertEqual(problems, [])
        self.assertEqual(entries[0]["password"], "pw\t\n")

    def test_not_json_and_not_a_list(self):
        for text in ("nonsense{", '{"label": "x"}', '"just a string"'):
            entries, problems = sc.parse_import_json(text)
            self.assertEqual(entries, [])
            self.assertEqual(len(problems), 1)

    def test_non_object_item(self):
        entries, problems = sc.parse_import_json('[42]')
        self.assertEqual(entries, [])
        self.assertIn("entry 1", problems[0])

    def test_non_string_value(self):
        entries, problems = sc.parse_import_json(
            '[{"label": "x", "password": 42}]')
        self.assertEqual(entries, [])
        self.assertIn("password must be a string", problems[0])

    def test_unknown_field_is_refused_not_dropped(self):
        entries, problems = sc.parse_import_json(
            '[{"label": "x", "usernmae": "typo"}]')
        self.assertEqual(entries, [])
        self.assertIn("usernmae", problems[0])

    def test_field_validation_applies(self):
        cases = ((json.dumps([{"label": "x" * 17}]), "label"),
                 ('[{"label": "has space"}]', "label"),
                 ('[{"label": "x", "group": "toolonggg"}]', "group"),
                 (json.dumps([{"label": "x", "password": "p" * 51}]),
                  "password"),
                 ('[{"label": "x", "username": "emoji \\ud83d\\ude00"}]',
                  "username"))
        for text, field in cases:
            entries, problems = sc.parse_import_json(text)
            self.assertEqual(entries, [], text)
            self.assertIn(field, problems[0])

    def test_duplicate_labels_fold_like_the_device(self):
        entries, problems = sc.parse_import_json(
            '[{"label": "Alpha"}, {"label": "ALPHA"}]')
        self.assertEqual(len(entries), 1)
        self.assertIn("entry 1", problems[0])

    def test_every_problem_is_reported_and_good_entries_survive(self):
        entries, problems = sc.parse_import_json(
            '[{"label": "ok"}, {"label": "bad label"}, {"label": "x", '
            '"password": 1}]')
        self.assertEqual(entries, [entry("ok")])
        self.assertEqual(len(problems), 2)

    def test_too_many_entries(self):
        text = json.dumps([{"label": f"l{i}"}
                           for i in range(sc.MAX_ENTRIES + 1)])
        entries, problems = sc.parse_import_json(text)
        self.assertEqual(entries, [])
        self.assertIn("at most", problems[0])


class ImportWorkerTests(unittest.TestCase):
    """The import_json request end to end against the stub."""

    def _drive(self, device, **data):
        path, _thread, _slave = stub_device.start_pty(device)
        transport = sc.PosixSerial(path)
        transport.open()
        out = queue.Queue()
        worker = sc.Worker(out)
        worker.transport = transport
        worker.session = sc.DeviceSession(transport)
        worker.start()
        try:
            worker.submit("import_json", **data)
            events = []
            while True:
                event = out.get(timeout=10)
                events.append(event)
                if event.name in ("import_done", "declined", "failed",
                                  "error", "disconnected"):
                    return events
        finally:
            worker.submit("quit")
            worker.join(timeout=5)

    def test_every_entry_is_sent_and_existing_labels_go_pending(self):
        # Existing labels are sent too - an import may update a stored
        # entry. The stub answers "exists" like firmware 2.6, whose
        # Replace prompt owns the outcome: the entry lands in `pending`.
        device = stub_device.FakeDevice()
        events = self._drive(device, entries=[
            entry("gmail", password="updated"),    # already on the device
            entry("new1", group="g", username="u", password="p"),
            entry("new2", password="p2")])
        names = [e.name for e in events]
        self.assertEqual(names.count("import_progress"), 3)
        done = events[-1]
        self.assertEqual(done.name, "import_done")
        self.assertEqual([a["label"] for a in done.data["added"]],
                         ["new1", "new2"])
        self.assertEqual(done.data["pending"], ["gmail"])
        self.assertEqual(done.data["declined"], [])
        self.assertEqual(device.entries["new1"]["password"], "p")
        # All three went on the wire; nothing enumerated first.
        self.assertEqual(device.op_counts.get(sc.OP_PUT_ENTRY, 0), 3)
        self.assertEqual(device.op_counts.get(sc.OP_GET_LABELIDX, 0), 0)

    def test_declined_entries_are_reported_and_the_rest_continue(self):
        device = stub_device.FakeDevice(always_abort=True)
        events = self._drive(device,
                             entries=[entry("new1"), entry("new2")])
        done = events[-1]
        self.assertEqual(done.name, "import_done")
        self.assertEqual(done.data["added"], [])
        self.assertEqual(done.data["declined"], ["new1", "new2"])
        self.assertNotIn("new1", device.entries)

    def test_a_full_device_stops_the_import(self):
        # The firmware refuses for space before it looks at the label, so
        # a full device stops replacements too - everything left is unsent.
        device = stub_device.FakeDevice()
        real_handle = device.handle

        def handle(payload):
            if payload[0] == sc.OP_PUT_ENTRY:
                return bytes([sc.ST_NO_SPACE])
            return real_handle(payload)

        device.handle = handle
        events = self._drive(device,
                             entries=[entry("new1"), entry("new2")])
        done = events[-1]
        self.assertEqual(done.data["added"], [])
        self.assertEqual(done.data["unsent"], ["new1", "new2"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

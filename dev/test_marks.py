#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 Seclave AB
"""Tests for the marker substitution that makes tab and newline visible.

No device and no Tk: the conversion is two pure functions. Run:
python3 dev/test_marks.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import seclave_companion as sc


def every_latin1_char():
    return "".join(chr(b) for b in range(256))


class MarkConversionTests(unittest.TestCase):

    # ---- the substitution itself ----

    def test_tab_and_newline_become_their_markers(self):
        self.assertEqual(sc.encode_marks("a\tb\nc"),
                         "a" + sc.MARK_TAB + "b" + sc.MARK_RET + "c")

    def test_markers_become_tab_and_newline(self):
        marked = "a" + sc.MARK_TAB + "b" + sc.MARK_RET + "c"
        self.assertEqual(sc.decode_marks(marked), "a\tb\nc")

    def test_carriage_return_has_no_marker(self):
        # The device's keyboard tables hold no entry for CR, so it is not
        # offered - it would spend a byte and type nothing.
        self.assertEqual(sc.encode_marks("a\rb"), "a\rb")

    def test_text_without_control_characters_is_untouched(self):
        self.assertEqual(sc.encode_marks("plain-password.1"),
                         "plain-password.1")

    # ---- round trip ----

    def test_round_trip_over_every_latin1_character(self):
        text = every_latin1_char()
        self.assertEqual(sc.decode_marks(sc.encode_marks(text)), text)

    def test_round_trip_of_a_field_that_is_only_controls(self):
        self.assertEqual(sc.decode_marks(sc.encode_marks("\t\n\t")), "\t\n\t")

    def test_both_directions_are_idempotent(self):
        # The boundary applies these at several points; a value that crossed
        # twice must not differ from one that crossed once.
        text = "user\tname\npart"
        once = sc.encode_marks(text)
        self.assertEqual(sc.encode_marks(once), once)
        back = sc.decode_marks(once)
        self.assertEqual(sc.decode_marks(back), back)

    # ---- why the substitution needs no escape scheme ----

    def test_no_marker_is_latin1_encodable(self):
        # The property the whole design rests on: the device stores Latin-1
        # only, so a marker can never be a character read back from one.
        for mark in (sc.MARK_TAB, sc.MARK_RET):
            self.assertIsNone(sc.latin1_safe(mark))

    def test_no_latin1_character_encodes_to_a_marker(self):
        encoded = sc.encode_marks(every_latin1_char())
        for mark in (sc.MARK_TAB, sc.MARK_RET):
            self.assertEqual(encoded.count(mark), 1)   # only from its control

    def test_a_marker_typed_into_a_field_survives_as_itself(self):
        # Decoding is the only way a marker leaves the UI, so a user who
        # pastes one in gets it rejected by the charset check, not silently
        # turned into a control character.
        self.assertIsNotNone(
            sc.validate_freeform(sc.MARK_TAB, sc.MAX_PASSWORD))

    # ---- what reaches the device ----

    def test_a_decoded_field_passes_validation_and_carries_the_bytes(self):
        marked = "pw" + sc.MARK_TAB + "next" + sc.MARK_RET
        value = sc.decode_marks(marked)
        self.assertIsNone(sc.validate_freeform(value, sc.MAX_PASSWORD))
        wire = sc.encode_field(sc.latin1(value))
        self.assertIn(0x09, wire)
        self.assertIn(0x0A, wire)

    def test_the_raw_marked_string_would_fail_the_charset_check(self):
        # Proves the ordering constraint the dialog has to honour: validate
        # what was decoded, never what the widget holds.
        marked = "pw" + sc.MARK_TAB
        self.assertIsNotNone(sc.validate_freeform(marked, sc.MAX_PASSWORD))
        self.assertIsNone(
            sc.validate_freeform(sc.decode_marks(marked), sc.MAX_PASSWORD))

    def test_a_marker_counts_as_the_one_byte_it_stands_for(self):
        marked = sc.MARK_TAB * 10
        self.assertEqual(len(sc.decode_marks(marked).encode("latin-1")), 10)

    def test_a_full_field_of_markers_is_exactly_at_the_limit(self):
        marked = sc.MARK_RET * sc.MAX_PASSWORD
        value = sc.decode_marks(marked)
        self.assertIsNone(sc.validate_freeform(value, sc.MAX_PASSWORD))
        self.assertIsNotNone(
            sc.validate_freeform(value + "\n", sc.MAX_PASSWORD))

    # ---- the restricted fields are not part of this ----

    def test_the_label_charset_admits_neither_marker_nor_control(self):
        for bad in (sc.MARK_TAB, sc.MARK_RET, "\t", "\n"):
            self.assertIsNotNone(
                sc.validate_restricted("ab" + bad, sc.MAX_LABEL, False))


if __name__ == "__main__":
    unittest.main(verbosity=1)

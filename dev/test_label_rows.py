#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 Seclave AB
"""Tests for LabelRows, the label table's mirror of the device.

No device and no Tk: the class is model only, which is why it lives outside
the UI guard in the shipped file. Run: python3 dev/test_label_rows.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import seclave_companion as sc


class LabelRowsTests(unittest.TestCase):
    def setUp(self):
        self.rows = sc.LabelRows()

    def names(self):
        return [row["label"] for row in self.rows.rows()]

    # ---- revealing ----

    def test_reveal_adds_only_the_revealed_column(self):
        self.rows.reveal("gmail", group="personal")
        row = self.rows.get("gmail")
        self.assertEqual(row["group"], "personal")
        self.assertIsNone(row["username"])
        self.assertIsNone(row["optional"])

    def test_reveal_of_a_new_label_adds_a_row(self):
        self.assertEqual(len(self.rows), 0)
        self.rows.reveal("gmail", group="personal")
        self.assertEqual(len(self.rows), 1)

    def test_reveal_does_not_claim_completeness(self):
        # Loading one entry says nothing about the rest of the device.
        self.rows.reveal("gmail", group="personal")
        self.assertFalse(self.rows.complete)

    def test_reveal_rejects_an_unknown_field(self):
        # The password is never tabled, so it is not a field here either.
        with self.assertRaises(KeyError):
            self.rows.reveal("gmail", password="hunter2")

    def test_empty_string_is_a_value_not_an_absence(self):
        self.rows.reveal("gmail", group="")
        self.assertEqual(self.rows.get("gmail")["group"], "")

    # ---- unreading one row ----

    def test_unread_forgets_only_the_named_fields_of_one_row(self):
        self.rows.reveal("gmail", group="personal", username="alice")
        self.rows.reveal("github", username="bob")
        self.rows.unread("gmail", "username")
        self.assertIsNone(self.rows.get("gmail")["username"])
        self.assertEqual(self.rows.get("gmail")["group"], "personal")
        self.assertEqual(self.rows.get("github")["username"], "bob")

    def test_unread_of_an_absent_row_is_a_no_op(self):
        self.rows.unread("nosuch", "username")
        self.assertIsNone(self.rows.get("nosuch"))

    def test_unread_rejects_an_unknown_field(self):
        self.rows.reveal("gmail", group="g")
        with self.assertRaises(KeyError):
            self.rows.unread("gmail", "label")

    # ---- full enumeration ----

    def test_replace_all_keeps_revealed_fields(self):
        self.rows.reveal("gmail", group="personal", username="alice")
        self.rows.replace_all(["gmail", "github"])
        row = self.rows.get("gmail")
        self.assertEqual((row["group"], row["username"]),
                         ("personal", "alice"))

    def test_replace_all_drops_labels_the_device_no_longer_has(self):
        self.rows.reveal("gone", group="x")
        self.rows.replace_all(["gmail"])
        self.assertIsNone(self.rows.get("gone"))
        self.assertEqual(self.names(), ["gmail"])

    def test_replace_all_adds_new_labels_unrevealed(self):
        self.rows.replace_all(["gmail"])
        row = self.rows.get("gmail")
        self.assertEqual([row[name] for name in sc.TABLE_FIELDS],
                         [None, None, None])

    def test_replace_all_sets_complete(self):
        self.assertFalse(self.rows.complete)
        self.rows.replace_all(["gmail"])
        self.assertTrue(self.rows.complete)

    def test_replace_all_adopts_the_device_spelling(self):
        # A label typed into the load-single box may differ in case from the
        # one the device stores; the device's spelling is the real one.
        self.rows.reveal("GMAIL", group="personal")
        self.rows.replace_all(["gmail"])
        self.assertEqual(self.names(), ["gmail"])
        self.assertEqual(self.rows.get("gmail")["group"], "personal")

    # ---- mutations that keep the mirror without re-reading ----

    def test_remove(self):
        self.rows.replace_all(["gmail", "github"])
        self.rows.remove("gmail")
        self.assertEqual(self.names(), ["github"])

    def test_remove_of_an_absent_label_is_harmless(self):
        self.rows.remove("nosuch")
        self.assertEqual(len(self.rows), 0)

    def test_replace_moves_the_row_to_the_new_label(self):
        self.rows.reveal("old", group="work", username="alice")
        self.rows.replace("old", "new", group="work", username="bob",
                          optional="note")
        self.assertIsNone(self.rows.get("old"))
        row = self.rows.get("new")
        self.assertEqual((row["group"], row["username"], row["optional"]),
                         ("work", "bob", "note"))

    def test_replace_with_an_unchanged_label_keeps_one_row(self):
        self.rows.reveal("gmail", group="personal")
        self.rows.replace("gmail", "gmail", group="work", username="alice",
                          optional="")
        self.assertEqual(self.names(), ["gmail"])
        self.assertEqual(self.rows.get("gmail")["group"], "work")

    # ---- forgetting (the detach wipe) ----

    def test_forget_clears_the_named_fields_in_every_row(self):
        self.rows.reveal("gmail", group="personal", username="alice",
                         optional="note")
        self.rows.reveal("github", group="work", username="bob")
        self.rows.forget("username", "optional")
        for label in ("gmail", "github"):
            row = self.rows.get(label)
            self.assertIsNone(row["username"])
            self.assertIsNone(row["optional"])

    def test_forget_keeps_the_other_fields(self):
        self.rows.reveal("gmail", group="personal", username="alice")
        self.rows.forget("username")
        self.assertEqual(self.rows.get("gmail")["group"], "personal")
        self.assertEqual(self.rows.get("gmail")["label"], "gmail")

    def test_forget_rejects_an_unknown_field(self):
        with self.assertRaises(KeyError):
            self.rows.forget("password")

    def test_forget_does_not_unhide_a_row(self):
        # Hiding is the user's choice; a detach wipe must not undo it - the
        # flag keeps covering whatever the user reveals again later.
        self.rows.reveal("gmail", group="personal", username="alice")
        self.rows.toggle_hidden("gmail")
        self.rows.forget("username", "optional")
        self.assertTrue(self.rows.get("gmail")["hidden"])

    # ---- hiding: display state, never forgetting ----

    def test_rows_start_unhidden(self):
        self.rows.reveal("gmail", group="personal")
        self.assertFalse(self.rows.get("gmail")["hidden"])

    def test_toggle_hidden_flips_and_reports_the_new_state(self):
        self.rows.reveal("gmail", group="personal")
        self.assertTrue(self.rows.toggle_hidden("gmail"))
        self.assertTrue(self.rows.get("gmail")["hidden"])
        self.assertFalse(self.rows.toggle_hidden("gmail"))
        self.assertFalse(self.rows.get("gmail")["hidden"])

    def test_hiding_forgets_nothing(self):
        self.rows.reveal("gmail", group="personal", username="alice")
        self.rows.toggle_hidden("gmail")
        row = self.rows.get("gmail")
        self.assertEqual((row["group"], row["username"]),
                         ("personal", "alice"))

    def test_hidden_survives_an_enumeration(self):
        # replace_all carries the row over, flag included: reloading the
        # label list must not uncover what the user chose to cover.
        self.rows.reveal("gmail", group="personal")
        self.rows.toggle_hidden("gmail")
        self.rows.replace_all(["gmail", "github"])
        self.assertTrue(self.rows.get("gmail")["hidden"])
        self.assertFalse(self.rows.get("github")["hidden"])

    def test_toggle_hidden_uses_the_device_fold(self):
        self.rows.reveal("gmail", group="personal")
        self.rows.toggle_hidden("GMAIL")
        self.assertTrue(self.rows.get("gmail")["hidden"])

    def test_an_edit_shows_the_row_again(self):
        # replace is a remove + reveal, so the row comes back unhidden: the
        # user just typed these values into the dialog themselves.
        self.rows.reveal("gmail", group="personal")
        self.rows.toggle_hidden("gmail")
        self.rows.replace("gmail", "gmail", group="work", username="alice",
                          optional="")
        self.assertFalse(self.rows.get("gmail")["hidden"])

    def test_hidden_is_not_a_revealable_field(self):
        # The flag is ours, not the device's - reveal() must not accept it.
        with self.assertRaises(KeyError):
            self.rows.reveal("gmail", hidden=True)

    # ---- ordering and identity follow the device ----

    def test_rows_are_sorted_lexically_ignoring_case(self):
        self.rows.replace_all(["zebra", "Apple", "monkey"])
        self.assertEqual(self.names(), ["Apple", "monkey", "zebra"])

    def test_a_revealed_label_sorts_into_place(self):
        self.rows.replace_all(["apple", "zebra"])
        self.rows.reveal("monkey", group="x")
        self.assertEqual(self.names(), ["apple", "monkey", "zebra"])

    def test_labels_differing_only_by_case_are_one_row(self):
        # The device looks labels up with latin1_strcasecmp, so it would find
        # one entry for both spellings; the mirror must agree.
        self.rows.reveal("Gmail", group="personal")
        self.rows.reveal("gmail", username="alice")
        self.assertEqual(len(self.rows), 1)
        row = self.rows.get("GMAIL")
        self.assertEqual((row["group"], row["username"]),
                         ("personal", "alice"))

    def test_the_devices_own_latin1_pairs_fold(self):
        # A-ring is one of the six two-case letters the device folds.
        self.rows.reveal("\xc5ngstrom", group="physics")
        self.assertIsNotNone(self.rows.get("\xe5ngstrom"))
        self.assertEqual(len(self.rows), 1)

    def test_letters_the_device_does_not_fold_stay_distinct(self):
        # E-acute has no case pair on the device (str.lower would fold it and
        # merge two entries that really are separate there).
        self.rows.reveal("caf\xc9", group="a")
        self.rows.reveal("caf\xe9", group="b")
        self.assertEqual(len(self.rows), 2)


if __name__ == "__main__":
    unittest.main(verbosity=1)

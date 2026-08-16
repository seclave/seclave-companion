#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 Seclave AB
"""Tests for the worker's edit flow, against a scripted stand-in session.

An edit must never delete first, and its answer must be honest on every
firmware: a rename adds the new entry before the old one goes; an in-place
edit is a single put whose replace the device either reports (2.7+) or
leaves pending behind its own prompt (2.6 and earlier), in which case only
the fields the edit changed become unknown. Run: python3 dev/test_edit_flow.py
"""

import os
import queue
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import seclave_companion as sc


class ScriptedSession:
    """Answers session calls from a script and records their order.

    `script` maps a method name to a list of outcomes, consumed one call at
    a time: an exception instance is raised, anything else returned. An
    unscripted call succeeds with None.
    """

    def __init__(self, **script):
        self.script = {name: list(outcomes)
                       for name, outcomes in script.items()}
        self.calls = []

    def _play(self, name, detail):
        self.calls.append((name, detail))
        outcomes = self.script.get(name)
        if not outcomes:
            return None
        outcome = outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def put_entry(self, label, group, username, password, optional):
        return self._play("put_entry", label)

    def del_entry(self, label):
        return self._play("del_entry", label)

    def get_group(self, label):
        return self._play("get_group", label)

    def put_wwwfill(self, domain, username, password):
        return self._play("put_wwwfill", (domain, username))

    def del_wwwfill(self, domain, username):
        return self._play("del_wwwfill", (domain, username))


def exists():
    return sc.DeviceError(sc.ST_LABEL_EXISTS)


class EditFlowTests(unittest.TestCase):
    def dispatch(self, session, name, **data):
        worker = sc.Worker(queue.Queue())
        worker.session = session
        worker._dispatch(sc.Request(name, **data))
        events = []
        while not worker.outq.empty():
            events.append(worker.outq.get())
        return events

    def edit(self, session, **overrides):
        data = dict(old_label="gmail", old_group="personal", changed=[],
                    label="gmail", group="personal", username="alice",
                    password="pw", optional="notes")
        data.update(overrides)
        return self.dispatch(session, "edit_entry", **data)

    # ---- rename: put first, delete after ----

    def test_rename_puts_before_deleting(self):
        session = ScriptedSession()
        events = self.edit(session, label="mail", changed=["username"])
        self.assertEqual(session.calls,
                         [("put_entry", "mail"), ("del_entry", "gmail")])
        (ev,) = events
        self.assertEqual((ev.name, ev.data["action"]), ("saved", "edit"))
        self.assertEqual(ev.data["old_label"], "gmail")
        self.assertNotIn("old_remains", ev.data)

    def test_rename_failed_delete_reports_leftover(self):
        session = ScriptedSession(del_entry=[sc.Cancelled()])
        (ev,) = self.edit(session, label="mail")
        self.assertEqual(ev.name, "saved")
        self.assertIn("declined", ev.data["old_remains"])

    def test_rename_failed_put_changes_nothing(self):
        session = ScriptedSession(put_entry=[sc.Cancelled()])
        with self.assertRaises(sc.Cancelled):
            self.edit(session, label="mail")
        self.assertEqual(session.calls, [("put_entry", "mail")])

    # ---- in-place edit, firmware that answers (2.7+) ----

    def test_inplace_ok_is_saved(self):
        session = ScriptedSession()
        (ev,) = self.edit(session, changed=["password"])
        self.assertEqual(session.calls, [("put_entry", "gmail")])
        self.assertEqual((ev.name, ev.data["action"]), ("saved", "edit"))

    def test_inplace_decline_reaches_the_caller(self):
        session = ScriptedSession(put_entry=[sc.Cancelled()])
        with self.assertRaises(sc.Cancelled):
            self.edit(session, changed=["password"])

    def test_other_device_errors_reach_the_caller(self):
        session = ScriptedSession(
            put_entry=[sc.DeviceError(sc.ST_NO_SPACE)])
        with self.assertRaises(sc.DeviceError):
            self.edit(session, changed=["password"])

    # ---- in-place edit, firmware that leaves the outcome pending ----

    def test_pending_marks_the_changed_fields(self):
        session = ScriptedSession(put_entry=[exists()])
        (ev,) = self.edit(session, changed=["username", "password"])
        self.assertEqual(ev.name, "save_pending")
        self.assertEqual(ev.data["changed"], ["username", "password"])

    def test_unchanged_edit_cannot_be_pending(self):
        session = ScriptedSession(put_entry=[exists()])
        (ev,) = self.edit(session, changed=[])
        self.assertEqual(ev.name, "saved")

    def test_changed_group_read_back_new_means_replaced(self):
        session = ScriptedSession(put_entry=[exists()],
                                  get_group=["work"])
        (ev,) = self.edit(session, group="work",
                          changed=["group", "password"])
        self.assertEqual((ev.name, ev.data["action"]), ("saved", "edit"))
        self.assertEqual(session.calls[-1], ("get_group", "gmail"))

    def test_changed_group_read_back_old_means_declined(self):
        session = ScriptedSession(put_entry=[exists()],
                                  get_group=["personal"])
        (ev,) = self.edit(session, group="work",
                          changed=["group", "password"])
        self.assertEqual(ev.name, "declined")

    def test_changed_group_read_back_declined_stays_pending(self):
        session = ScriptedSession(put_entry=[exists()],
                                  get_group=[sc.Cancelled()])
        (ev,) = self.edit(session, group="work", changed=["group"])
        self.assertEqual(ev.name, "save_pending")

    # ---- web edits ----

    def web_edit(self, session, **overrides):
        data = dict(old_domain="shop.example.com", old_username="buyer",
                    domain="shop.example.com", username="buyer",
                    password="pw")
        data.update(overrides)
        return self.dispatch(session, "edit_wwwfill", **data)

    def test_web_rename_puts_before_deleting(self):
        session = ScriptedSession()
        (ev,) = self.web_edit(session, username="owner")
        self.assertEqual(session.calls,
                         [("put_wwwfill", ("shop.example.com", "owner")),
                          ("del_wwwfill", ("shop.example.com", "buyer"))])
        self.assertEqual(ev.name, "saved")
        self.assertNotIn("old_remains", ev.data)

    def test_web_rename_failed_delete_reports_leftover(self):
        session = ScriptedSession(del_wwwfill=[sc.Cancelled()])
        (ev,) = self.web_edit(session, username="owner")
        self.assertEqual(ev.name, "saved")
        self.assertIn("shop.example.com / buyer", ev.data["old_pair"])

    def test_web_same_pair_ok_is_saved(self):
        session = ScriptedSession()
        (ev,) = self.web_edit(session, password="new")
        self.assertEqual(session.calls,
                         [("put_wwwfill", ("shop.example.com", "buyer"))])
        self.assertEqual(ev.name, "saved")

    def test_web_same_pair_exists_is_pending(self):
        session = ScriptedSession(put_wwwfill=[exists()])
        (ev,) = self.web_edit(session, password="new")
        self.assertEqual((ev.name, ev.data["view"]), ("save_pending", "web"))

    def test_web_domain_case_only_edit_is_the_same_pair(self):
        session = ScriptedSession()
        (ev,) = self.web_edit(session, domain="SHOP.example.com")
        self.assertEqual(session.calls,
                         [("put_wwwfill", ("SHOP.example.com", "buyer"))])
        self.assertEqual(ev.name, "saved")


if __name__ == "__main__":
    unittest.main(verbosity=2)

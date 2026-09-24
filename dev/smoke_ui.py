#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 Seclave AB
"""Dev-only headless smoke test of the Tk UI against the stub device.

Instantiates the real App against a PTY stub, pumps the Tk event loop by hand
(no user), and asserts the table loads, search filters, and a password fetch
copies to the clipboard. Run under a display or xvfb:

    xvfb-run -a python3 dev/smoke_ui.py
"""

import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import seclave_companion as sc
import stub_device


def pump(app, seconds):
    """Run the Tk loop for a while without blocking on mainloop()."""
    end = time.time() + seconds
    while time.time() < end:
        app.update()
        app.update_idletasks()
        time.sleep(0.02)


def main():
    device = stub_device.FakeDevice(delay=0.0)
    path, _thread, _slave = stub_device.start_pty(device)

    app = sc.App(forced_port=path)
    pump(app, 1.5)  # let the port poll connect
    assert app.connected, "app did not connect to the stub port"
    assert not app.labels.complete and not app.web_loaded

    # Both discovery stages ran over the wire: the stub answered the
    # reserved domain with the capability marker, and the query that
    # follows it with the version and store usage.
    assert app.fw_version == "2.7", app.fw_version
    assert (app.fw_used, app.fw_total) == (6, 500), (app.fw_used, app.fw_total)
    assert app._device_at_least(2, 7) and not app._device_at_least(3, 0)
    assert "2.7" in app.status.cget("text"), app.status.cget("text")

    # Pre-oracle firmware answers not-found; the app flags it and carries on.
    device.fw_version = None
    app.worker.submit("query_version")
    pump(app, 0.5)
    assert app.fw_version is None
    assert not app._device_at_least(2, 7)
    assert "2.6 or earlier" in app.status.cget("text"), app.status.cget("text")

    # That answer was definite, so a reconnect reports it straight from
    # memory - no second probe, no wait.
    assert app.skip_version_probe
    app._ev_connected({"port": path})
    pump(app, 0.3)
    assert not app.busy
    assert "2.6 or earlier" in app.status.cget("text"), app.status.cget("text")

    device.fw_version = "2.7"
    print("version oracle: 2.7 detected, pre-2.7 fallback and its "
          "remembered flag work")

    # Loading while the device is believed pre-2.7 enumerates labels only -
    # no wwwfill prefetch, no group enumeration, groups stay unread.
    app._load()
    pump(app, 1.0)
    assert app.labels.complete and not app.web_loaded
    assert device.op_counts.get(sc.OP_GET_LABELIDX, 0) > 0
    assert device.op_counts.get(sc.OP_GET_LABELGROUPIDX, 0) == 0
    assert device.op_counts.get(sc.OP_GET_WWWFILLIDX, 0) == 0, "prefetched wwwfill"
    assert len(app.labels) >= 3, "labels did not load: %r" % app.labels.rows()
    labels = [r["label"] for r in app.labels.rows()]
    assert "gmail" in labels, labels
    assert app.labels.get("gmail")["group"] is None
    print("pre-2.7 load: %d label rows, groups unread" % len(app.labels))

    # Pre-2.7 has no group enumeration, so a normal load leaves the Group
    # column unread. The "Load view + groups" button is offered for exactly
    # this case; it reads each group with GET_GROUP after the label walk. The
    # stub answers promptly (delay 0), so nothing is sensed as prompting.
    assert app.load_groups_btn.winfo_ismapped(), "group button hidden pre-2.7"
    op14_before = device.op_counts.get(sc.OP_GET_LABELGROUPIDX, 0)
    app._load_groups()
    pump(app, 1.0)
    assert device.op_counts.get(sc.OP_GET_LABELGROUPIDX, 0) == op14_before, \
        "pre-2.7 group load must not send op 14"
    assert device.op_counts.get(sc.OP_GET_GROUP, 0) > 0, "no per-label reads"
    assert app.labels.get("gmail")["group"] == "personal"
    print("pre-2.7 'Load view + groups' fills groups with per-label reads")

    # Probed back to 2.7, the same load carries the group along - one
    # enumeration, one confirmation, no per-label group reads.
    app.skip_version_probe = False
    app.worker.submit("query_version")
    pump(app, 0.5)
    assert app._device_at_least(2, 7)
    group_reads = device.op_counts.get(sc.OP_GET_GROUP, 0)
    app._load()
    pump(app, 1.0)
    assert device.op_counts.get(sc.OP_GET_LABELGROUPIDX, 0) > 0
    assert device.op_counts.get(sc.OP_GET_GROUP, 0) == group_reads
    assert app.labels.get("gmail")["group"] == "personal"
    # On 2.7+ the group button is pointless - the normal load already carries
    # groups - so it hides.
    pump(app, 0.2)
    assert not app.load_groups_btn.winfo_ismapped(), "group button shown on 2.7"
    print("2.7 load fills label+group in one enumeration")

    # Search filter narrows the table.
    app.search_var.set("gmail")
    app._render()
    assert app.tree.get_children(), "search filter hid everything"
    visible = [app.row_by_iid[i]["label"] for i in app.tree.get_children()]
    assert visible == ["gmail"], visible
    app.search_var.set("")
    app._render()

    # The label view has an Optional column, blanked until fetched.
    assert "optional" in app.tree["columns"], app.tree["columns"]
    gmail_row = app.labels.get("gmail")
    assert gmail_row["optional"] is None

    # Select gmail and fetch its password -> lands on the clipboard.
    def select(label):
        for iid in app.tree.get_children():
            if app.row_by_iid[iid].get("label") == label:
                app.tree.selection_set(iid)
                return
    select("gmail")
    app._copy("password")
    pump(app, 0.6)
    assert app.clipboard_get() == "hunter2", repr(app.clipboard_get())
    print("password fetch reached clipboard OK")

    # The timed clear overwrites rather than disowns: a selection owner
    # with nothing to serve hangs some terminals' paste (Alacritty), so a
    # single space stands in for "nothing".
    app._clear_clipboard()
    assert app.clipboard_get() == " ", repr(app.clipboard_get())
    assert app.clip_value is None
    print("clipboard clear leaves a space, not an empty-handed owner")

    # ...and it reads before it writes: content the user copied somewhere
    # else in the meantime is not ours to clobber. (A copy racing the
    # overwrite itself can still lose - accepted, the window is tiny.)
    app._put_clipboard("ours")
    app.clipboard_clear()
    app.clipboard_append("theirs")
    app._clear_clipboard()
    assert app.clipboard_get() == "theirs", repr(app.clipboard_get())
    assert app.clip_value is None
    print("clipboard clear leaves foreign content alone")

    # Copy optional: fetches once (revealing it in the table), then reuses
    # the shown value with no second device read.
    select("gmail")
    app._copy_optional()
    pump(app, 0.6)
    assert gmail_row["optional"] == "notes", repr(gmail_row["optional"])
    assert app.clipboard_get() == "notes", repr(app.clipboard_get())
    fetches = device.op_counts[sc.OP_GET_OPTIONAL]
    select("gmail")
    app._copy_optional()
    pump(app, 0.3)
    assert device.op_counts[sc.OP_GET_OPTIONAL] == fetches, "refetched optional"
    print("copy optional reveals + caches OK")

    # Hide fields masks the revealed values in the table but keeps them: a
    # copy still comes from the cache with no device read, and a second
    # toggle shows the values again.
    select("gmail")
    app._toggle_hidden()
    pump(app, 0.2)
    values = app.tree.item(app.tree.selection()[0], "values")
    assert sc.HIDDEN_FIELD in values and "notes" not in values, values
    app._copy_optional()
    pump(app, 0.3)
    assert device.op_counts[sc.OP_GET_OPTIONAL] == fetches, "read behind the mask"
    assert app.clipboard_get() == "notes", repr(app.clipboard_get())
    app._toggle_hidden()
    pump(app, 0.2)
    values = app.tree.item(app.tree.selection()[0], "values")
    assert "notes" in values, values
    print("hide fields masks the table, cache and copy keep working")

    # Show entry fetches every field into a read-only viewer window; the row's
    # non-secret columns update, the password is never cached.
    select("gmail")
    app._show_entry()
    pump(app, 0.6)
    viewer = next(w for w in app.winfo_children()
                  if isinstance(w, sc.EntryViewer))
    shown = {}
    for child in viewer.winfo_children():
        if child.winfo_class() == "TEntry":
            shown[child.grid_info()["row"]] = child.get()
    assert list(shown.values()) == ["gmail", "personal", "alice@example.com",
                                    "hunter2", "notes"], shown
    assert gmail_row["username"] == "alice@example.com"
    assert "password" not in gmail_row
    viewer.destroy()
    print("show-entry viewer holds all five fields")

    # The viewer's Edit button switches to the edit dialog with the same
    # just-fetched values - no second round of device confirmations.
    select("gmail")
    app._show_entry()
    pump(app, 0.6)
    viewer = next(w for w in app.winfo_children()
                  if isinstance(w, sc.EntryViewer))
    field_ops = (sc.OP_GET_GROUP, sc.OP_GET_USERNAME, sc.OP_GET_PASSWORD,
                 sc.OP_GET_OPTIONAL)
    reads = sum(device.op_counts.get(op, 0) for op in field_ops)
    viewer._edit()
    pump(app, 0.3)
    assert not viewer.winfo_exists()
    dialog = next(w for w in app.winfo_children()
                  if isinstance(w, sc.EntryDialog))
    got = {k: dialog.vars[k].get() for k in
           ("label", "group", "username", "password", "optional")}
    assert got == {"label": "gmail", "group": "personal",
                   "username": "alice@example.com", "password": "hunter2",
                   "optional": "notes"}, got
    assert dialog.existing["_old_label"] == "gmail"
    assert sum(device.op_counts.get(op, 0) for op in field_ops) == reads, \
        "switching viewer to edit refetched fields"
    dialog.destroy()
    print("viewer switches to edit without refetching")

    # The username stands revealed after Show entry, so a copy of it reuses
    # the table's value instead of asking the device again.
    user_reads = device.op_counts.get(sc.OP_GET_USERNAME, 0)
    select("gmail")
    app._copy("username")
    pump(app, 0.3)
    assert device.op_counts.get(sc.OP_GET_USERNAME, 0) == user_reads, \
        "refetched a revealed username"
    assert app.clipboard_get() == "alice@example.com", repr(app.clipboard_get())
    print("copy username reuses the revealed value")

    # Hiding masks the sensitive fields only - the revealed group stays
    # shown, keeping the row findable while covered.
    select("gmail")
    app._toggle_hidden()
    pump(app, 0.2)
    values = app.tree.item(app.tree.selection()[0], "values")
    assert "personal" in values, values
    assert "alice@example.com" not in values, values
    app._toggle_hidden()
    pump(app, 0.2)
    print("hide keeps the group visible")

    # Load single entry on a label already in the mirror is answered locally.
    group_reads = device.op_counts.get(sc.OP_GET_GROUP, 0)
    app.load_single_var.set("gmail")
    app._load_single()
    pump(app, 0.3)
    assert device.op_counts.get(sc.OP_GET_GROUP, 0) == group_reads, \
        "reloaded an already-loaded entry"
    assert not app.busy
    print("load single entry skips an already-loaded label")

    # Edit opens the dialog prefilled with the device's current values.
    select("gmail")
    app._edit()
    pump(app, 0.6)
    dialog = next(w for w in app.winfo_children()
                  if isinstance(w, sc.EntryDialog))
    got = {k: dialog.vars[k].get() for k in
           ("label", "group", "username", "password", "optional")}
    assert got == {"label": "gmail", "group": "personal",
                   "username": "alice@example.com", "password": "hunter2",
                   "optional": "notes"}, got
    assert dialog.existing["_old_label"] == "gmail"
    dialog.destroy()
    print("edit dialog prefilled from the device")

    # A real add through the dialog: Save disarms the button, the put runs,
    # and its OK closes the dialog - no read-back, the put's own status is
    # the device's answer.
    group_reads = device.op_counts.get(sc.OP_GET_GROUP, 0)
    dlg = sc.EntryDialog(app, app.mono, app._on_dialog_save)
    dlg.vars["label"].set("fromdlg")
    dlg.vars["group"].set("smoke")
    dlg.vars["password"].set("pw")
    dlg._save()
    assert str(dlg.save_btn.cget("state")) == "disabled"
    pump(app, 1.0)
    assert not dlg.winfo_exists(), "dialog stayed after a successful save"
    assert device.op_counts.get(sc.OP_GET_GROUP, 0) == group_reads, \
        "a plain add should not read anything back"
    row = app.labels.get("fromdlg")
    assert row and row["group"] == "smoke", row
    assert "Added fromdlg" in app.status.cget("text"), app.status.cget("text")
    print("add answered by the put alone, dialog closed")

    # After the fetches and saves above, the table still shows the default
    # order: lexical by label under the device's case fold.
    assert app.sort_col is None
    shown = [app.row_by_iid[i]["label"] for i in app.tree.get_children()]
    assert shown == sorted(shown, key=sc.latin1_fold), shown

    # A header click sorts ascending under the same fold, a second flips
    # descending, a third restores the default label order.
    app._sort_by("username")
    assert (app.sort_col, app.sort_desc) == ("username", False)
    by_user = [app.row_by_iid[i]["username"] or "" for i in app.tree.get_children()]
    assert by_user == sorted(by_user, key=sc.latin1_fold), by_user
    app._sort_by("username")
    assert (app.sort_col, app.sort_desc) == ("username", True)
    app._sort_by("username")
    assert app.sort_col is None
    shown = [app.row_by_iid[i]["label"] for i in app.tree.get_children()]
    assert shown == sorted(shown, key=sc.latin1_fold), shown
    print("default label order kept; header sort cycles back to it")

    # A failed save re-arms the dialog with the values still in it - the
    # typed password survives for another try.
    dlg = sc.EntryDialog(app, app.mono, app._on_dialog_save)
    dlg.vars["label"].set("kept")
    dlg.vars["password"].set("s3cret")
    app.pending_dialog = dlg
    app._ev_declined({"request": "put_entry"})
    assert dlg.winfo_exists() and app.pending_dialog is None
    assert dlg.vars["password"].get() == "s3cret"
    assert str(dlg.save_btn.cget("state")) == "normal"
    dlg.destroy()
    print("failed save keeps the dialog and its values")

    # A rename adds the new label before the old one goes: the credential
    # exists on the device at every step, and the row follows the new name.
    device.entries["ren"] = dict(group="g", username="u", password="p",
                                 optional="")
    dlg = sc.EntryDialog(app, app.mono, app._on_dialog_save,
                         existing={"web": False, "label": "ren",
                                   "group": "g", "username": "u",
                                   "password": "p", "optional": "",
                                   "_old_label": "ren"})
    dlg.vars["label"].set("ren2")
    dlg._save()
    pump(app, 1.0)
    assert not dlg.winfo_exists(), "rename did not close the dialog"
    assert "ren2" in device.entries and "ren" not in device.entries, \
        sorted(device.entries)
    assert app.labels.get("ren2")["group"] == "g"
    assert app.labels.get("ren") is None
    print("rename lands as put-new then delete-old")

    # An in-place edit against firmware that answers "exists" (the stub
    # mimics 2.6: it refuses and keeps the old record): the outcome belongs
    # to the device's Replace prompt, so the fields the edit changed turn
    # unread and the dialog closes - nothing is lost either way.
    dlg = sc.EntryDialog(app, app.mono, app._on_dialog_save,
                         existing={"web": False, "label": "ren2",
                                   "group": "g", "username": "u",
                                   "password": "p", "optional": "",
                                   "_old_label": "ren2"})
    dlg.vars["username"].set("u2")
    dlg._save()
    pump(app, 1.0)
    assert not dlg.winfo_exists(), "pending edit did not close the dialog"
    row = app.labels.get("ren2")
    assert row["username"] is None and row["group"] == "g", row
    assert "Replace" in app.status.cget("text"), app.status.cget("text")
    print("pending in-place edit marks changed fields unread")

    # The same edit with the group changed settles itself: one group read
    # queues behind the device's prompt and answers with the surviving
    # record. The stub kept the old one, which reads as a decline - the
    # dialog re-arms with the values still in it.
    dlg = sc.EntryDialog(app, app.mono, app._on_dialog_save,
                         existing={"web": False, "label": "ren2",
                                   "group": "g", "username": "u",
                                   "password": "p", "optional": "",
                                   "_old_label": "ren2"})
    dlg.vars["group"].set("g2")
    dlg._save()
    pump(app, 1.0)
    assert dlg.winfo_exists(), "declined edit should re-arm the dialog"
    assert str(dlg.save_btn.cget("state")) == "normal"
    assert dlg.vars["group"].get() == "g2"
    assert app.labels.get("ren2")["group"] == "g"
    dlg.destroy()
    print("declined in-place edit detected through the group read")

    # A put onto a label the mirror knows is refused before it can raise the
    # device's replace prompt for an entry the user did not mean to touch.
    problem = app._on_dialog_save(
        {"web": False, "label": "gmail", "group": "", "username": "",
         "password": "", "optional": ""}, None)
    assert problem and "already exists" in problem, problem
    assert not app.busy
    print("label collision refused client-side")

    # Length counters: muted under the cap, red once the field is full (the
    # device truncates silently past it).
    dlg = sc.EntryDialog(app, app.mono, app._on_dialog_save)
    pump(app, 0.3)
    lbl_counter = dlg.rows["label"][2]
    lbl_entry = dlg.rows["label"][1]
    dlg.vars["label"].set("short")
    pump(app, 0.1)
    assert lbl_counter.cget("text") == "5/16", lbl_counter.cget("text")
    assert str(lbl_counter.cget("foreground")) == sc.STYLE["muted"]
    dlg.vars["label"].set("x" * 16)
    pump(app, 0.1)
    assert lbl_counter.cget("text") == "16/16", lbl_counter.cget("text")
    assert str(lbl_counter.cget("foreground")) == sc.STYLE["red"]
    assert str(lbl_entry.cget("foreground")) == sc.STYLE["red"]
    dlg.vars["label"].set("x" * 17)
    pump(app, 0.1)
    assert str(lbl_counter.cget("foreground")) == sc.STYLE["red"]
    dlg.destroy()
    print("length counter turns red at the cap")

    # Switching to the web view enumerates wwwfill lazily - the first time only.
    app.view_var.set("Web passwords (wwwfill)")
    app._switch_view()
    pump(app, 1.0)
    assert app.view == "web"
    assert app.web_loaded
    assert device.op_counts.get(sc.OP_GET_WWWFILLIDX, 0) > 0
    web_calls = device.op_counts[sc.OP_GET_WWWFILLIDX]
    web_domains = [app.row_by_iid[i]["domain"] for i in app.tree.get_children()]
    assert "github.com" in web_domains, web_domains
    print("web view lazily loaded %d rows" % len(web_domains))

    # Switch away and back: already loaded this session, so no re-enumeration.
    app.view_var.set("All labels")
    app._switch_view()
    pump(app, 0.3)
    app.view_var.set("Web passwords (wwwfill)")
    app._switch_view()
    pump(app, 0.3)
    assert device.op_counts[sc.OP_GET_WWWFILLIDX] == web_calls, "refetched wwwfill"
    print("view switch back is local (no refetch)")

    # Duplicate refusal: a web save colliding with an existing
    # (domain, username) - domain case-insensitive - is refused client-side
    # (_on_dialog_save returns the message for the dialog) and never reaches
    # the device.
    puts_before = device.op_counts.get(sc.OP_PUT_WWWFILL, 0)
    problem = app._on_dialog_save(
        {"web": True, "domain": "GitHub.com", "username": "alice",
         "password": "x"}, None)
    assert problem, "duplicate web save was not refused"
    pump(app, 0.3)
    assert device.op_counts.get(sc.OP_PUT_WWWFILL, 0) == puts_before
    assert not app.busy
    print("duplicate web save refused client-side")

    # The name version discovery probes cannot be given a web password: an
    # entry stored under it would shadow the probe on firmware that does not
    # reserve it. Refused client-side, in any casing, before the device sees
    # anything.
    for domain in (sc.VERSION_DOMAIN, "\xd6\xd6\xd6SECLAVE.VERSION"):
        problem = app._on_dialog_save(
            {"web": True, "domain": domain, "username": "u",
             "password": "p"}, None)
        assert problem and "reserved" in problem, (domain, problem)
        pump(app, 0.3)
        assert device.op_counts.get(sc.OP_PUT_WWWFILL, 0) == puts_before
        assert not app.busy
    print("reserved version-discovery name refused for web saves")

    # A non-duplicate save goes through and the view refreshes.
    problem = app._on_dialog_save(
        {"web": True, "domain": "shop.example.com", "username": "buyer",
         "password": "x"}, None)
    assert problem is None, problem
    pump(app, 1.0)
    assert ("shop.example.com", "buyer") in [
        (r["domain"], r["username"]) for r in app.web_rows]
    print("non-duplicate web save accepted")

    # Staleness gating: after (say) a disconnect the cached web list is no
    # longer known-fresh; a web save then triggers a reload instead of either
    # trusting the stale cache or silently sending the write.
    app.web_loaded = False
    web_calls_before = device.op_counts[sc.OP_GET_WWWFILLIDX]
    problem = app._on_dialog_save(
        {"web": True, "domain": "another.example.com", "username": "u",
         "password": "x"}, None)
    assert problem and "load" in problem.lower(), problem
    pump(app, 0.6)
    assert app.web_loaded, "stale-cache save did not trigger a reload"
    assert device.op_counts[sc.OP_GET_WWWFILLIDX] > web_calls_before
    assert device.op_counts.get(sc.OP_PUT_WWWFILL, 0) == puts_before + 1
    print("stale web cache triggers reload before save")

    # Load-time scan: a device that already holds a duplicate pair (the
    # pre-lock state the pre-send refusal cannot prevent) triggers a warning
    # dialog when the web view loads. Patch the blocking messagebox for the
    # headless run; edit/delete of the pair stays refused either way.
    warned = []
    real_showwarning = sc.messagebox.showwarning
    sc.messagebox.showwarning = lambda *args, **kw: warned.append(args)
    try:
        app._ev_loaded_web({"web": [("dup.example.com", "u"),
                                    ("DUP.example.com", "u")]})
    finally:
        sc.messagebox.showwarning = real_showwarning
    assert len(warned) == 1, warned
    assert "dup.example.com" in warned[0][1], warned
    print("pre-existing device duplicate warned at load")

    # Same at load time for the reserved name: an old device may already hold
    # one, put there by another tool. It is warned about, but the row stays
    # listed so the user can delete it from here.
    warned = []
    real_showwarning = sc.messagebox.showwarning
    sc.messagebox.showwarning = lambda *args, **kw: warned.append(args)
    try:
        app._ev_loaded_web({"web": [(sc.VERSION_DOMAIN, "u")]})
    finally:
        sc.messagebox.showwarning = real_showwarning
    assert len(warned) == 1, warned
    assert "reserved" in warned[0][1], warned
    assert (sc.VERSION_DOMAIN, "u") in [
        (r["domain"], r["username"]) for r in app.web_rows], app.web_rows
    print("stored reserved name warned at load, row still listed")

    # The Tab and Enter keys put a marker in the field, and what the device
    # is asked to store is the control character it stands for.
    puts_before = device.op_counts.get(sc.OP_PUT_ENTRY, 0)
    dlg = sc.EntryDialog(app, app.mono, app._on_dialog_save)
    dlg.vars["label"].set("marked")
    entry = dlg.rows["password"][1]
    entry.insert("end", "pw")
    # Each key lands at the insertion cursor, not at the end of the field.
    entry.icursor("end")
    dlg._insert_mark("password", sc.MARK_RET)
    entry.icursor(0)
    dlg._insert_mark("password", sc.MARK_TAB)
    assert dlg.vars["password"].get() == sc.MARK_TAB + "pw" + sc.MARK_RET, \
        dlg.vars["password"].get()
    assert dlg._field("password") == "\tpw\n", repr(dlg._field("password"))
    # A marker stands for one byte, so the counter reads 4 and not 2.
    assert dlg.rows["password"][2].cget("text") == f"4/{sc.MAX_PASSWORD}", \
        dlg.rows["password"][2].cget("text")
    dlg._save()
    pump(app, 1.0)
    assert not dlg.winfo_exists(), "marked save left the dialog open"
    assert device.op_counts.get(sc.OP_PUT_ENTRY, 0) == puts_before + 1
    assert device.entries["marked"]["password"] == "\tpw\n", \
        repr(device.entries["marked"]["password"])
    print("Tab and Enter keys store real control characters")

    # A pasted control character normalizes to its marker, so nothing sits in
    # the field invisibly - and a pasted CR becomes the newline it meant.
    dlg = sc.EntryDialog(app, app.mono, app._on_dialog_save)
    dlg.vars["username"].set("a\tb\r\nc\rd")
    assert dlg.vars["username"].get() == \
        "a" + sc.MARK_TAB + "b" + sc.MARK_RET + "c" + sc.MARK_RET + "d", \
        dlg.vars["username"].get()
    assert dlg._field("username") == "a\tb\nc\nd", repr(dlg._field("username"))
    # The restricted fields get no keys and no normalizing: a control
    # character pasted there is refused rather than made to look storable.
    dlg.vars["label"].set("bad\tlabel")
    assert dlg.vars["label"].get() == "bad\tlabel"
    dlg._save()
    assert "not allowed" in dlg.error.cget("text"), dlg.error.cget("text")
    # A web entry has no optional field, so its keys go with it - they sit in
    # a frame of their own and would otherwise be left behind on an empty row.
    dlg.is_web.set(True)
    dlg._refresh_fields()
    pump(app, 0.2)
    assert not dlg.extras["optional"].winfo_ismapped(), \
        "the optional field's keys outlived the field"
    assert dlg.extras["password"].winfo_ismapped()
    dlg.is_web.set(False)
    dlg._refresh_fields()
    pump(app, 0.2)
    assert dlg.extras["optional"].winfo_ismapped()
    dlg.destroy()
    print("pasted controls become markers; restricted fields refuse them")

    # Read-back shows the markers again, in the table and in the viewer.
    app.view_var.set("All labels")
    app._switch_view()
    app.labels.reveal("marked", username="u\tv")
    app._render()
    shown = [app.tree.item(i, "values") for i in app.tree.get_children()
             if app.row_by_iid[i]["label"] == "marked"]
    assert shown and "u" + sc.MARK_TAB + "v" in shown[0], shown
    viewer = sc.EntryViewer(app, app.mono,
                            {"web": False, "label": "marked",
                             "username": "u\tv", "password": "p\nq",
                             "group": "", "optional": ""})
    assert viewer.vars[2].get() == "u" + sc.MARK_TAB + "v", viewer.vars[2].get()
    assert viewer.vars[3].get() == "p" + sc.MARK_RET + "q", viewer.vars[3].get()
    viewer.destroy()
    print("stored controls show as markers in the table and the viewer")

    # Import JSON: the file validates as a whole, then every entry is sent -
    # existing labels included, so an import can update passwords. The stub
    # answers "exists" for github like firmware 2.6, whose Replace prompt
    # owns the outcome: the row's fields turn unread. Nothing is enumerated
    # first. The blocking dialogs are patched away for the headless run.
    import tempfile as _tf
    puts_before = device.op_counts.get(sc.OP_PUT_ENTRY, 0)
    enum_before = device.op_counts.get(sc.OP_GET_LABELIDX, 0)
    assert app.labels.get("github")["group"] == "work"
    infos = []
    real_open = sc.filedialog.askopenfilename
    real_ok = sc.messagebox.askokcancel
    real_info = sc.messagebox.showinfo
    with _tf.TemporaryDirectory() as tmp:
        ipath = os.path.join(tmp, "import.json")
        with open(ipath, "w", encoding="utf-8") as fh:
            fh.write(sc.entries_to_json([
                {"label": "imported1", "group": "imp", "username": "iu",
                 "password": "ip", "optional": "io"},
                {"label": "github", "group": "work", "username": "alice",
                 "password": "updated", "optional": ""}]))
        sc.filedialog.askopenfilename = lambda **kw: ipath
        sc.messagebox.askokcancel = lambda *a, **kw: True
        sc.messagebox.showinfo = lambda *a, **kw: infos.append(a)
        try:
            app._import_json()
            pump(app, 1.0)
        finally:
            sc.filedialog.askopenfilename = real_open
            sc.messagebox.askokcancel = real_ok
            sc.messagebox.showinfo = real_info
    assert device.entries["imported1"]["password"] == "ip"
    assert device.entries["github"]["password"] == "octocat!", \
        "the stub's Replace outcome belongs to the device"
    assert device.op_counts.get(sc.OP_PUT_ENTRY, 0) == puts_before + 2
    assert device.op_counts.get(sc.OP_GET_LABELIDX, 0) == enum_before, \
        "import enumerated the labels"
    row = app.labels.get("imported1")
    assert row and row["group"] == "imp" and row["username"] == "iu", row
    assert app.labels.get("github")["group"] is None, \
        "a pending Replace must unread the row"
    assert infos and "Added or updated 1 of 2" in infos[0][1], infos
    assert "Replace" in infos[0][1], infos
    assert "Added or updated 1 of 2" in app.status.cget("text"), \
        app.status.cget("text")
    assert not app.busy
    print("json import sends everything; a met label defers to the "
          "device's Replace")

    # A detach clears every revealed field except label and group - back to
    # not-read, so the next look is confirmed again.
    gmail_row = app.labels.get("gmail")
    assert gmail_row["username"] == "alice@example.com"
    assert gmail_row["optional"] == "notes"
    app._ev_disconnected({})
    assert gmail_row["username"] is None and gmail_row["optional"] is None
    assert gmail_row["group"] == "personal"
    assert not app.labels.complete and not app.web_loaded
    print("detach wipes all but label+group")

    # ---- offline backup: the open dialog, the viewer, the exports ----

    # The full path a user takes: pick the archive, type the key (watch it
    # group itself), Open - the decrypt thread posts back and the viewer
    # appears. The fixture is the firmware-generated golden archive.
    golden_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "golden_backup.bkp")
    dlg = sc.OpenBackupDialog(app, app.mono, app._start_backup_decrypt)
    app.backup_dialog = dlg
    dlg.path_var.set(golden_path)
    # Type the key keystroke by keystroke: the dashes appear as the groups
    # fill, and - the regression - the cursor follows them, so no character
    # lands before the one it was typed after. The regrouping is deferred to
    # idle time (see _format_key), which the pump provides.
    dlg.key_entry.focus_force()
    pump(app, 0.1)
    for ch in "c24c6d83e5bdbf999dda1fe0e90a5d02":
        dlg.key_entry.event_generate("<Key>", keysym=ch)
        app.update()
    pump(app, 0.2)
    assert dlg.key_var.get() == "C24C6D83-E5BDBF99-9DDA1FE0-E90A5D02", \
        dlg.key_var.get()
    assert dlg.key_entry.index("insert") == len(dlg.key_var.get())
    dlg._open()
    pump(app, 2.5)
    assert not dlg.winfo_exists(), "successful open left the dialog"
    viewer = next(w for w in app.winfo_children()
                  if isinstance(w, sc.BackupViewer))
    rows = [viewer.row_by_iid[i]["label"] for i in viewer.tree.get_children()]
    assert rows == ["aws-root", "github", "gmail"], rows
    values = viewer.tree.item(viewer.tree.get_children()[0], "values")
    assert "s3cr3t-root" not in values, values   # no password in the table
    print("open backup dialog decrypts into the viewer")

    # A wrong key re-arms the dialog with the message; path and key stay.
    dlg = sc.OpenBackupDialog(app, app.mono, app._start_backup_decrypt)
    app.backup_dialog = dlg
    dlg.path_var.set(golden_path)
    dlg.key_var.set("0" * 32)
    dlg._open()
    pump(app, 2.5)
    assert dlg.winfo_exists(), "failed open should keep the dialog"
    assert str(dlg.open_btn.cget("state")) == "normal"
    assert "does not match" in dlg.error.cget("text"), dlg.error.cget("text")
    assert dlg.path_var.get() == golden_path
    dlg.destroy()
    app.backup_dialog = None
    print("wrong backup key re-arms the dialog")

    # Search narrows; the password bar fills on request for the selected row
    # and empties the moment the selection moves.
    viewer.search_var.set("gmail")
    viewer._render()
    assert len(viewer.tree.get_children()) == 1
    viewer.search_var.set("")
    viewer._render()

    def viewer_select(label):
        for iid in viewer.tree.get_children():
            if viewer.row_by_iid[iid]["label"] == label:
                viewer.tree.selection_set(iid)
                return
    viewer_select("gmail")
    pump(app, 0.2)
    viewer._toggle_password()
    assert viewer.pw_var.get() == "hunter2", viewer.pw_var.get()
    viewer_select("aws-root")
    pump(app, 0.2)
    assert viewer.pw_var.get() == "", "password bar outlived its row"
    print("viewer search + show/hide password work")

    # Show entry opens the same read-only viewer the live table uses, with
    # every field of the backup entry - and no Edit button (nothing to edit).
    viewer_select("gmail")
    pump(app, 0.2)
    viewer._show_entry()
    pump(app, 0.2)
    shown_viewer = next(w for w in viewer.winfo_children()
                        if isinstance(w, sc.EntryViewer))
    shown = {}
    for child in shown_viewer.winfo_children():
        if child.winfo_class() == "TEntry":
            shown[child.grid_info()["row"]] = child.get()
    assert list(shown.values()) == ["gmail", "persona", "alice@example.com",
                                    "hunter2", "notes"], shown
    shown_viewer.destroy()
    print("viewer's show-entry holds all five fields")

    # Exports land every entry, password included, in each format.
    import tempfile as _tempfile
    real_ask = sc.filedialog.asksaveasfilename
    with _tempfile.TemporaryDirectory() as tmp:
        for kind, check in (
                ("json", lambda t: "s3cr3t-root" in t and t.startswith("[")),
                ("csv", lambda t: "s3cr3t-root" in t and
                    t.startswith(",".join(sc.EXPORT_FIELDS))),
                ("yaml", lambda t: '"s3cr3t-root"' in t and
                    t.startswith("- label:"))):
            target = os.path.join(tmp, "out." + kind)
            sc.filedialog.asksaveasfilename = lambda **kw: target
            try:
                viewer._export(kind)
            finally:
                sc.filedialog.asksaveasfilename = real_ask
            with open(target, encoding="utf-8") as fh:
                text = fh.read()
            assert check(text), (kind, text[:100])
            assert "passwords included" in viewer.status.cget("text")
    viewer.destroy()
    print("viewer exports json/csv/yaml with passwords")

    app._clear_clipboard()
    app.destroy()
    print("SMOKE OK")


if __name__ == "__main__":
    main()

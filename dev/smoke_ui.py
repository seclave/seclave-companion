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

    app._clear_clipboard()
    app.destroy()
    print("SMOKE OK")


if __name__ == "__main__":
    main()

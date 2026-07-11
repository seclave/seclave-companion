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
    assert not app.labels_loaded and not app.web_loaded

    # Loading the (default) labels view enumerates labels only - not wwwfill.
    app._load()
    pump(app, 1.0)
    assert app.labels_loaded and not app.web_loaded
    assert device.op_counts.get(sc.OP_GET_LABELIDX, 0) > 0
    assert device.op_counts.get(sc.OP_GET_WWWFILLIDX, 0) == 0, "prefetched wwwfill"
    assert len(app.label_rows) >= 3, "labels did not load: %r" % app.label_rows
    labels = [r["label"] for r in app.label_rows]
    assert "gmail" in labels, labels
    print("loaded %d label rows (wwwfill not prefetched)" % len(app.label_rows))

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
    gmail_row = next(r for r in app.label_rows if r["label"] == "gmail")
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
    app.group_var.set("Web passwords (wwwfill)")
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
    app.group_var.set("All labels")
    app._switch_view()
    pump(app, 0.3)
    app.group_var.set("Web passwords (wwwfill)")
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

    app._clear_clipboard()
    app.destroy()
    print("SMOKE OK")


if __name__ == "__main__":
    main()

# Seclave Companion

A desktop table view for a Seclave 2.0 hardware password manager, over the
device's USB-slave (CDC-ACM serial) protocol. It enumerates the entries stored
on the device into a searchable, sortable table and lets you copy a username or
password, add an entry, edit one, or delete one - each secret action confirmed
on the device's own screen.

It is one self-contained Python file using only the standard library: no pip
installs, no background service, and nothing written to disk. Secrets are read
from the device only when you ask for them, copied to the clipboard, and the
clipboard clears after 30 seconds and on exit.

The real security boundary is the Seclave itself - its display and joystick,
where you see and approve each action. This app is a convenience front-end.

### Secrets in memory

Every host-side copy of a secret lives in mmap pages the app zeroes explicitly:
bytes are read from the serial port straight into an anonymous mmap arena (never
into an intermediate Python `bytes`), parsed in place, copied mmap-to-mmap into a
per-secret buffer, and the arena is wiped after every command. The two copies the
app cannot control are the kernel's tty receive buffer and the transient string
created at the moment a value is shown or placed on the clipboard (which the
clipboard and windowing system may then retain). The app does not lock pages into
RAM, and makes no claim of complete zeroization - the device's on-screen
confirmation, not host memory hygiene, is what actually protects your secrets.

## Before you start

Put the device in USB-slave mode: on the Seclave, open the menu and select
**Usb slave**. The serial port only exists while the device is in that menu and
disappears when you leave it (or press UP). Launch the app, then click
**Load view**.

Labels and web passwords are loaded separately, on demand - one device
confirmation each. Loading the labels view confirms "Show all labels"; switching
the Group dropdown to **Web passwords (wwwfill)** the first time confirms "Show
all wwwfills". Each view is fetched only when you first show it, and switching
back to a view you already loaded this session is instant with no new prompt.

Access modes affect whether the device prompts you. In **Normal** (the default)
and **Ask all** modes, most reads pause on the device until you press the
joystick to confirm - the app shows a red "Look at your Seclave" alert bar
while it waits. In **Allow all** mode nothing prompts and reads return at once. Web
passwords (wwwfill) are read and written without a prompt in Normal mode; that
path is intentionally frictionless.

## Running it

### Any platform: pipx or uv

If you have pipx or uv (common on developer machines), this installs the
`seclave_companion` command on your PATH:

```
pipx install seclave-companion        # or: uv tool install seclave-companion
seclave_companion
```

The Python running it must have Tk: python.org installers include it, uv's
managed Pythons include it, Homebrew needs `brew install python-tk`, and
Debian/Ubuntu needs `sudo apt install python3-tk`. On Linux you still need
serial access (see the packaged udev rule below); on macOS and Windows the
port works as-is.

### Linux

The recommended way is the package (built by
`packaging/linux/build_linux_packages.sh`):

```
sudo apt install ./seclave-companion_<version>_all.deb    # Debian/Ubuntu
sudo dnf install ./seclave-companion-<version>.noarch.rpm # Fedora/RHEL
```

It installs `seclave_companion` on your PATH, a desktop menu entry, and a udev
rule that keeps ModemManager off the port (it otherwise probes the new serial
device and can corrupt the first exchange), grants the logged-in user access
with no group setup, and creates a stable `/dev/seclave` symlink. Plug the
device in, put it in USB-slave mode, run `seclave_companion`.

To run from source instead, install Tk and start the file directly:

- Debian/Ubuntu: `sudo apt install python3-tk`
- Fedora: `sudo dnf install python3-tkinter`
- Arch: `sudo pacman -S tk`

```
python3 seclave_companion.py
```

Running from source you handle serial access yourself: add your user to the
`dialout` group, or install the packaged udev rule
(`packaging/linux/60-seclave.rules`) by hand.

### Windows

Install Python 3 from python.org - it includes Tk. Then double-click the file or
run:

```
py seclave_companion.py
```

### macOS

Install Python 3 from python.org - it bundles a working Tk 8.6. Apple's system
Python does not have a usable Tk. Then run:

```
python3 seclave_companion.py
```

## What it does and does not do

- Reads the entry list, searches and sorts it, and switches to a web-passwords
  view. Copies a username, password, or the Optional field (notes/domain) on
  demand; fields read this way stay shown in the table. Show entry displays
  every field of a row in a read-only window (password masked until you tick
  "show"). Adds,
  edits (as delete-then-add, with the dialog prefilled from the device), and
  deletes entries. Generates passwords.
- It does not do bulk import or backup - those are better suited to the device's
  faster mass-storage path and are handled by separate tooling.

## Developer tooling

The `dev/` directory is not part of the shipped program. It lets you work
without hardware:

- `dev/stub_device.py` - a fake Seclave speaking the protocol over a
  pseudo-terminal. Run it to get a port path, then point the app at it:

  ```
  python3 dev/stub_device.py          # prints e.g. /dev/pts/7
  python3 seclave_companion.py --port /dev/pts/7
  ```

  Options: `--delay SECONDS` simulates the confirmation pause; `--abort` makes
  the device decline every confirmable command.

- `dev/test_protocol.py` - end-to-end tests of the protocol layer against the
  stub: `python3 dev/test_protocol.py`.
- `dev/smoke_ui.py` - a headless check that the window loads, filters, and
  copies a password: `xvfb-run -a python3 dev/smoke_ui.py` (or run it under any
  display).

## Releasing

**Bump `VERSION` in `seclave_companion.py` (near the top). That is the only
version written by hand.** Then commit, and tag the commit `v<version>`:

```
git tag v1.2.0
git push origin v1.2.0
```

Everything else derives from `VERSION`, so there is nothing else to keep in
step:

| Artifact | How it gets the version |
|---|---|
| PyPI sdist/wheel | `pyproject.toml` reads the `VERSION` attribute (`dynamic = ["version"]`) |
| `.deb` / `.rpm` | `build_linux_packages.sh` greps it and passes it to nfpm |
| Windows version resource | generated by `packaging/windows/make_version_info.py` |
| `SeclaveCompanion.exe` | PyInstaller stamps it from that resource |
| Installer + its filename | the Inno script reads `ProductVersion` back out of the packaged exe |
| Artifact filenames | the build scripts, from the same value |

The tag is the one stamp that cannot be derived - it is the input that starts
a release - so CI checks it against `VERSION` and fails the run if they
disagree. A `-rc.N` suffix is ignored by that check: `v1.2.0-rc.1` rehearses
the release of `1.2.0`, produces a draft prerelease, and deliberately skips
the PyPI upload so a rehearsal cannot burn the version (PyPI uploads are
immutable). Delete rehearsal tags and their draft releases afterwards.

Pushing the tag builds everything - deb, rpm, portable zip, one-file exe,
console exe, installer - on real Linux and Windows runners, attaches them with
`SHA256SUMS.txt` to a **draft** release, and publishes to PyPI on final tags.
The draft is yours to review, GPG-sign the checksums for, and publish. See
`.github/workflows/release.yml`.

To build locally without CI: `sh packaging/linux/build_linux_packages.sh`,
`powershell -File packaging\windows\build_windows.ps1` on Windows, or
`sh packaging/windows/build_on_wine.sh` to cross-build the Windows set on
Ubuntu. A Wine-built binary still has to be tested on real Windows before it
ships.

## License

MIT - see the [LICENSE](LICENSE) file.

Seclave is a trademark of Seclave AB. This license grants no trademark rights.

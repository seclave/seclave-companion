# -*- mode: python ; coding: utf-8 -*-
# PyInstaller build spec for the Seclave Companion Windows executable.
#
# Paths below are relative to the repo root; build from the repo root on a
# Windows machine (PyInstaller does not cross-compile):
#
#     py -m pip install pyinstaller
#     py -m PyInstaller packaging\windows\seclave_companion.spec
#
# Output: dist\SeclaveCompanion\SeclaveCompanion.exe plus its support files
# (one-dir mode; kinder to antivirus heuristics than one-file, and it lets the
# installer lay the files down without a self-extraction step).
#
# Expects assets/seclave.ico in the repo (multi-size app icon). The Windows
# version resource is generated here from VERSION in the app, so the spec is
# self-sufficient and the version is never typed twice.
#
# No INF is bundled: Windows 10/11 bind the inbox usbser.sys driver by USB
# class matching, and the app finds the port by VID/PID.

import sys

sys.path.insert(0, SPECPATH)
from make_version_info import write_version_info

version_file = write_version_info()

a = Analysis(
    ['../../seclave_companion.py'],
    pathex=[],
    binaries=[],
    # MIT wants the notice to travel with every copy. The Linux packages carry
    # it as their distribution copyright file; on Windows it rides in the
    # bundle, which is also what the installer lays down.
    datas=[('../../LICENSE', '.')],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='SeclaveCompanion',
    debug=False,
    strip=False,
    upx=False,               # UPX-packed exes are a classic antivirus tripwire
    console=False,           # windowed app: no console box behind the Tk window
    icon='../../assets/seclave.ico',
    version=version_file,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name='SeclaveCompanion',
)

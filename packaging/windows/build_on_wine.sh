#!/bin/sh
# Fallback: build the Windows artifacts on plain Ubuntu with no Windows box
# and no CI, by running the *Windows* CPython + PyInstaller (and Inno Setup)
# under Wine. CI uses build_windows.ps1 on a real Windows runner instead.
#
# Run from the repo root on Ubuntu 24.04+ (verified: 26.04 / Wine 10.0). Needs:
#   sudo apt-get install -y --no-install-recommends wine wine64 winbind xvfb
# Everything else (Windows Python, PyInstaller, Inno Setup) is fetched into a
# Wine prefix under ~/.cache on first run (~1.4 GB; delete the prefix to reset).
#
# Produces in dist/, versioned from VERSION in seclave_companion.py:
#   SeclaveCompanion/                       one-dir bundle
#   SeclaveCompanion-<version>-portable.zip zipped one-dir bundle
#   SeclaveCompanion-<version>.exe          single self-contained exe
#   SeclaveCompanion-Setup-<version>.exe    installer (WITH_INSTALLER=0 skips)
#   SHA256SUMS.txt                          checksums
#
# A Wine-built exe MUST still pass a real-Windows test before release; this
# script saves a build machine, not the verification.
set -eu

# Pinned toolchain - the combination verified working 2026-07-21. Wine builds
# are version-coupled; bump these together and re-verify, don't float them.
PYTHON_VERSION=3.13.5
PYINSTALLER_VERSION=6.21.0
INNOSETUP_VERSION=6.7.3

export WINEPREFIX="${WINEPREFIX:-$HOME/.cache/seclave-winebuild}"
export WINEDEBUG=-all
export WINEDLLOVERRIDES=mscoree=d   # skip the Wine-Mono download prompt
CACHE="$WINEPREFIX-downloads"
WINEPY="$WINEPREFIX/drive_c/Python/python.exe"
ISCC="$WINEPREFIX/drive_c/Program Files (x86)/Inno Setup 6/ISCC.exe"

command -v wine >/dev/null || {
    echo "wine not found - sudo apt-get install -y --no-install-recommends wine wine64 winbind xvfb" >&2
    exit 1
}
# Installers and Tk need an X display; use the real one if present, Xvfb if not.
if [ -n "${DISPLAY:-}" ]; then RUN=; else RUN="xvfb-run -a"; fi

mkdir -p "$CACHE"
if [ ! -f "$WINEPY" ]; then
    installer="python-$PYTHON_VERSION-amd64.exe"
    [ -f "$CACHE/$installer" ] || \
        curl -fL -o "$CACHE/$installer" "https://www.python.org/ftp/python/$PYTHON_VERSION/$installer"
    $RUN wine "$CACHE/$installer" /quiet "TargetDir=C:\\Python" \
        Include_doc=0 InstallAllUsers=1 PrependPath=1
fi
wine "$WINEPY" -m pip install --quiet --no-warn-script-location \
    "pyinstaller==$PYINSTALLER_VERSION"

# The protocol tests drive the pty stub (POSIX-only), so run them with the
# native Python; the Wine Python is only for freezing.
python3 dev/test_protocol.py

VERSION=$(sed -n 's/^VERSION = "\(.*\)"/\1/p' seclave_companion.py)
[ -n "$VERSION" ] || { echo "no VERSION in seclave_companion.py" >&2; exit 1; }

# The Windows version resource is generated from VERSION (the spec does this
# too); the one-file builds below need the path up front.
VERSION_FILE=$(python3 packaging/windows/make_version_info.py)

# Adopted repo layout has the spec (icon, version resource);
# fall back to a bare one-dir build so the script also works pre-adoption.
if [ -f packaging/windows/seclave_companion.spec ]; then
    $RUN wine "$WINEPY" -m PyInstaller --noconfirm packaging/windows/seclave_companion.spec
else
    $RUN wine "$WINEPY" -m PyInstaller --noconfirm --onedir --windowed \
        --name SeclaveCompanion seclave_companion.py
fi

(cd dist && python3 -c "import shutil; \
    shutil.make_archive('SeclaveCompanion-$VERSION-portable', 'zip', '.', 'SeclaveCompanion')")

# Single-file build: same icon and version resource, self-extracting at launch.
$RUN wine "$WINEPY" -m PyInstaller --noconfirm --onefile --windowed \
    --name SeclaveCompanion --icon assets/seclave.ico \
    --version-file "$VERSION_FILE" \
    --distpath dist_onefile --workpath build_onefile seclave_companion.py
cp dist_onefile/SeclaveCompanion.exe "dist/SeclaveCompanion-$VERSION.exe"

# Console variant for reading --debug output live.
$RUN wine "$WINEPY" -m PyInstaller --noconfirm --onefile --console \
    --name SeclaveCompanion-console --icon assets/seclave.ico \
    --version-file "$VERSION_FILE" \
    --distpath dist_console --workpath build_console seclave_companion.py
cp dist_console/SeclaveCompanion-console.exe "dist/SeclaveCompanion-$VERSION-console.exe"

if [ "${WITH_INSTALLER:-1}" = 1 ] && [ -f packaging/windows/seclave_companion.iss ]; then
    if [ ! -f "$ISCC" ]; then
        setup="innosetup-$INNOSETUP_VERSION.exe"
        tag="is-$(echo "$INNOSETUP_VERSION" | tr . _)"
        [ -f "$CACHE/$setup" ] || curl -fL -o "$CACHE/$setup" \
            "https://github.com/jrsoftware/issrc/releases/download/$tag/$setup"
        $RUN wine "$CACHE/$setup" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
    fi
    $RUN wine "$ISCC" /Qp packaging/windows/seclave_companion.iss
fi

(cd dist && sha256sum "SeclaveCompanion-$VERSION-portable.zip" \
    "SeclaveCompanion-$VERSION.exe" "SeclaveCompanion-$VERSION-console.exe" \
    "SeclaveCompanion-Setup-$VERSION.exe" > SHA256SUMS.txt)

echo "Done. Test the artifacts on real Windows before publishing."

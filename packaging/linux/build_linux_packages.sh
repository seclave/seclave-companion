#!/bin/sh
# Build the Seclave Companion .deb and .rpm with nfpm. Run from the repo root:
#
#     sh packaging/linux/build_linux_packages.sh
#
# nfpm is fetched into ~/.cache on first run. Output lands in dist/.
#
# The version comes from VERSION in seclave_companion.py, so bumping the app
# is the only bump needed.
set -eu

NFPM_VERSION=2.43.1

VERSION=$(sed -n 's/^VERSION = "\(.*\)"/\1/p' seclave_companion.py)
[ -n "$VERSION" ] || { echo "no VERSION in seclave_companion.py" >&2; exit 1; }
export VERSION

[ -f assets/seclave-companion.png ] || {
    echo "missing assets/seclave-companion.png (256x256 icon)" >&2; exit 1; }

NFPM="$HOME/.cache/seclave-nfpm/nfpm"
if [ ! -x "$NFPM" ]; then
    mkdir -p "${NFPM%/*}"
    curl -fL "https://github.com/goreleaser/nfpm/releases/download/v$NFPM_VERSION/nfpm_${NFPM_VERSION}_Linux_x86_64.tar.gz" \
        | tar -xz -C "${NFPM%/*}" nfpm
fi

mkdir -p dist
for fmt in deb rpm; do
    "$NFPM" package -f packaging/linux/nfpm.yaml -p "$fmt" -t dist/
done

(cd dist && ls -1 seclave-companion*_"$VERSION"* seclave-companion-"$VERSION"* 2>/dev/null || true)
echo "Done. Install: sudo apt install ./dist/<deb>  or  sudo dnf install ./dist/<rpm>"

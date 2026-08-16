App icons used by the packaging (tracked so CI can build without external
staging):

- `seclave-companion.png` - 256x256, installed as the hicolor icon by the
  Linux packages.
- `seclave.ico` - 48px + 256px, embedded in the Windows executable by the
  PyInstaller spec.
- `screenshot.png` - the label table, shown in the README. Captured headlessly
  against the development stub device, so every entry in it is invented.

The Seclave logo is a trademark of Seclave AB. The MIT license of this
repository grants no trademark rights; do not reuse these icons for anything
other than building this application.

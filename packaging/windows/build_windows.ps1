# Build every Windows artifact on a real Windows machine (or CI runner).
# Run from the repo root:
#
#     powershell -ExecutionPolicy Bypass -File packaging\windows\build_windows.ps1
#
# Needs: Python 3.13 on PATH, PyInstaller (pinned below), Inno Setup 6
# (preinstalled on GitHub runners; installed via choco here if missing).
# Output lands in dist\ with version-stamped names, same as the Linux and
# Wine scripts.
$ErrorActionPreference = "Stop"

$pyinstallerVersion = "6.21.0"

$version = (Select-String -Path seclave_companion.py -Pattern '^VERSION = "(.*)"').Matches.Groups[1].Value
if (-not $version) { throw "no VERSION in seclave_companion.py" }

# Everything downstream is stamped from that one number: the version resource
# is generated from it, and the installer reads its version back out of the
# built exe.
$versionFile = python packaging\windows\make_version_info.py

python -m pip install --quiet "pyinstaller==$pyinstallerVersion"

# One-dir bundle + portable zip.
python -m PyInstaller --noconfirm packaging\windows\seclave_companion.spec
Compress-Archive -Force -Path dist\SeclaveCompanion `
    -DestinationPath "dist\SeclaveCompanion-$version-portable.zip"

# Single-file exe, and the console variant for reading --debug output live.
python -m PyInstaller --noconfirm --onefile --windowed --name SeclaveCompanion `
    --icon assets\seclave.ico --version-file $versionFile `
    --distpath dist_onefile --workpath build_onefile seclave_companion.py
Copy-Item dist_onefile\SeclaveCompanion.exe "dist\SeclaveCompanion-$version.exe"
python -m PyInstaller --noconfirm --onefile --console --name SeclaveCompanion-console `
    --icon assets\seclave.ico --version-file $versionFile `
    --distpath dist_console --workpath build_console seclave_companion.py
Copy-Item dist_console\SeclaveCompanion-console.exe "dist\SeclaveCompanion-$version-console.exe"

# Installer.
$iscc = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if (-not (Test-Path $iscc)) {
    choco install innosetup -y --no-progress
}
& $iscc /Qp packaging\windows\seclave_companion.iss
if ($LASTEXITCODE -ne 0) { throw "ISCC failed" }

Get-ChildItem dist\SeclaveCompanion-*

; Inno Setup 6 script for the Seclave Companion Windows installer.
;
; Build on Windows after the PyInstaller step has produced
; dist\SeclaveCompanion\ (one-dir bundle):
;
;     iscc packaging\windows\seclave_companion.iss
;
; Output: dist\SeclaveCompanion-Setup-<version>.exe
;
; No COM-port INF ships: Windows 10/11 bind the Microsoft inbox usbser.sys
; driver to the device by USB class matching, and the app finds the port by
; USB VID/PID. driver_install_snippet.py keeps the pnputil recipe for the
; older-Windows case.

#define MyAppName "Seclave Companion"
#define MyAppExeName "SeclaveCompanion.exe"
; Read back out of the exe being packaged (PyInstaller stamped it from VERSION
; in seclave_companion.py), so the installer cannot disagree with its payload.
#define MyAppVersion GetStringFileInfo("..\..\dist\SeclaveCompanion\" + MyAppExeName, PRODUCT_VERSION)

[Setup]
; Fixed for the life of the product: upgrades replace the previous install.
AppId={{8B5F0405-CACA-41FB-8FCE-DA9C017AE766}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=Seclave AB
AppPublisherURL=https://www.seclave.se
DefaultDirName={autopf}\Seclave\{#MyAppName}
DefaultGroupName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
OutputDir=..\..\dist
OutputBaseFilename=SeclaveCompanion-Setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; Admin install: puts the app in Program Files.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; Flags: unchecked

[Files]
Source: "..\..\dist\SeclaveCompanion\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

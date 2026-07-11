#!/bin/sh
# Reload udev so the Seclave rule applies without a reboot, and re-trigger in
# case the device is already plugged in. In a container or chroot there is no
# udev to talk to; that is fine, the rule applies from the next boot.
if command -v udevadm >/dev/null 2>&1; then
    udevadm control --reload-rules 2>/dev/null || true
    udevadm trigger --subsystem-match=usb --subsystem-match=tty 2>/dev/null || true
fi
exit 0

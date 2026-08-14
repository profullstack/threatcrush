#!/bin/bash
# Replaces electron-builder's stock deb postrm. The update-alternatives block is
# carried over verbatim from app-builder-lib's `templates/linux/after-remove.tpl`;
# only the AppArmor cleanup is ours. See after-install.sh.

# Delete the link to the binary
if type update-alternatives >/dev/null 2>&1; then
    update-alternatives --remove '${executable}' '/usr/bin/${executable}'
else
    rm -f '/usr/bin/${executable}'
fi

# Remove the profile installed by after-install.sh. Unloading before deleting,
# because a profile removed from disk while still loaded stays in the kernel
# until the next reboot — and it names a path that no longer has a binary at it.
APPARMOR_PROFILE='/etc/apparmor.d/${executable}'
if [ -f "$APPARMOR_PROFILE" ]; then
    if command -v apparmor_parser >/dev/null 2>&1; then
        apparmor_parser -R "$APPARMOR_PROFILE" >/dev/null 2>&1 || true
    fi
    rm -f "$APPARMOR_PROFILE"
fi

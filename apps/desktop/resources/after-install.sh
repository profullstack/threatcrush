#!/bin/bash
# Replaces electron-builder's stock deb postinst. Naming `deb.afterInstall` in
# electron-builder.yml *overrides* the default template rather than appending
# to it, so the update-alternatives / mime / desktop-database blocks below are
# carried over verbatim from app-builder-lib's `templates/linux/after-install.tpl`.
# Only the sandbox section is ours. Keep the rest in sync when bumping
# electron-builder.

if type update-alternatives 2>/dev/null >&1; then
    # Remove previous link if it doesn't use update-alternatives
    if [ -L '/usr/bin/${executable}' -a -e '/usr/bin/${executable}' -a "`readlink '/usr/bin/${executable}'`" != '/etc/alternatives/${executable}' ]; then
        rm -f '/usr/bin/${executable}'
    fi
    update-alternatives --install '/usr/bin/${executable}' '${executable}' '/opt/${sanitizedProductName}/${executable}' 100 || ln -sf '/opt/${sanitizedProductName}/${executable}' '/usr/bin/${executable}'
else
    ln -sf '/opt/${sanitizedProductName}/${executable}' '/usr/bin/${executable}'
fi

# ── Sandbox ──────────────────────────────────────────────────────────────────
#
# The stock template picks between Chromium's two sandboxes like this:
#
#     if ! { [[ -L /proc/self/ns/user ]] && unshare --user true; }; then
#         chmod 4755 chrome-sandbox   # no user namespaces -> SUID sandbox
#     else
#         chmod 0755 chrome-sandbox   # namespaces work -> SUID not needed
#     fi
#
# That asks the right question as the wrong user, at the wrong time. A postinst
# runs as root, and Ubuntu 24.04+'s `kernel.apparmor_restrict_unprivileged_userns`
# restricts *unprivileged* user namespaces only — root is exempt. So the probe
# succeeds during install, the else branch runs, chrome-sandbox lands as 0755,
# and the first ordinary launch dies with:
#
#     The SUID sandbox helper binary was found, but is not configured
#     correctly. Rather than run without sandboxing I'm aborting now.
#
# Two things are done about it, in order of preference.
#
# First, an AppArmor profile granting this binary `userns create`. That restores
# the *namespace* sandbox, which is the one upstream Chromium actually develops
# against; the SUID helper is a compatibility path for kernels without userns.
# Shipping the profile is what Chrome, Chromium and the other Electron apps in
# the archive settled on for this exact regression.
#
# Second, the SUID bit, as a fallback — decided by probing as an unprivileged
# user rather than as root, so the answer reflects the conditions the app will
# actually run under. `nobody` is the probe subject because it is the one
# account guaranteed to exist and guaranteed not to be privileged.
CHROME_SANDBOX='/opt/${sanitizedProductName}/chrome-sandbox'
APPARMOR_PROFILE='/etc/apparmor.d/${executable}'

userns_available_unprivileged() {
    # No unprivileged probe subject means no trustworthy answer. Report "not
    # available", which selects the SUID sandbox — a sandbox that is merely
    # unnecessary costs nothing, while wrongly skipping it aborts the app.
    command -v runuser >/dev/null 2>&1 || return 1
    id nobody >/dev/null 2>&1 || return 1
    runuser -u nobody -- unshare --user true >/dev/null 2>&1
}

if [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)" = "1" ] \
    && [ -d /etc/apparmor.d ]; then
    cat > "$APPARMOR_PROFILE" <<'APPARMOR_EOF'
# Grants the namespace sandbox to ThreatCrush Desktop on kernels where
# unprivileged user namespaces are restricted by AppArmor (Ubuntu 24.04+).
# flags=(unconfined) keeps this a permission grant, not a confinement policy:
# it does not restrict the application beyond the system default.
abi <abi/4.0>,
include <tunables/global>

profile ${executable} "/opt/${sanitizedProductName}/${executable}" flags=(unconfined) {
  userns,
  include if exists <local/${executable}>
}
APPARMOR_EOF

    # Best-effort. A parser that rejects the profile (an older abi, say) must
    # not fail the package install — the SUID fallback below still applies.
    if command -v apparmor_parser >/dev/null 2>&1; then
        apparmor_parser -r -W "$APPARMOR_PROFILE" >/dev/null 2>&1 \
            || echo 'threatcrush: could not load AppArmor profile; falling back to the SUID sandbox' >&2
    fi
fi

if userns_available_unprivileged; then
    chmod 0755 "$CHROME_SANDBOX" || true
else
    chmod 4755 "$CHROME_SANDBOX" || true
fi

if hash update-mime-database 2>/dev/null; then
    update-mime-database /usr/share/mime || true
fi

if hash update-desktop-database 2>/dev/null; then
    update-desktop-database /usr/share/applications || true
fi

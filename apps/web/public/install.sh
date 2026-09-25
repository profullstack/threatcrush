#!/bin/sh
set -e

# ThreatCrush installer
# Usage: curl -fsSL https://threatcrush.com/install.sh | sh

BOLD="\033[1m"
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
DIM="\033[2m"
RESET="\033[0m"

PKG_NAME="@profullstack/threatcrush"
# The desktop app is an Electron bundle published to GitHub Releases (.dmg /
# .exe / .AppImage / .deb), not to npm. There is nothing to install globally.
DESKTOP_RELEASES_URL="https://github.com/profullstack/threatcrush/releases/latest"
MISE_INSTALL_URL="https://mise.run"
CONFIG_DIR="$HOME/.threatcrush"
CONFIG_PATH="$CONFIG_DIR/install.json"

say() {
  printf "%b\n" "$1"
}

say ""
say "${GREEN}  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗${RESET}"
say "${GREEN}  ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝${RESET}"
say "${GREEN}     ██║   ███████║██████╔╝█████╗  ███████║   ██║   ${RESET}"
say "${GREEN}     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ${RESET}"
say "${GREEN}     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ${RESET}"
say "${GREEN}     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝${RESET}"
say "${DIM}                    C R U S H${RESET}"
say ""

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

have_sudo() {
  if [ "$(id -u)" -eq 0 ]; then
    return 0
  fi
  command_exists sudo
}

# npm first, deliberately. It ships with Node, and its global install is the one
# path that behaves the same on every machine. The alternatives each have a way
# to fail a `curl | sh` run that the user never opted into:
#   pnpm  - `pnpm add -g` aborts when its global bin dir is not already on PATH,
#           the global dir layout is versioned (v9/v10 use `global/5`, v11 uses
#           `global/v11`) so two pnpm versions on one box fight over it, and the
#           global pnpm-lock.yaml pins the resolved version, so a reinstall can
#           silently hand back an older release than `latest`.
#   yarn  - `yarn global add` is removed in Yarn 2+.
#   bun   - `bun add -g` links into ~/.bun/bin, which is often not on PATH.
# Anyone who wants a different package manager can still install by hand; the
# installer should pick the boring option that works unattended.
detect_pm() {
  if command_exists npm; then echo "npm"
  elif command_exists pnpm; then echo "pnpm"
  elif command_exists yarn; then echo "yarn"
  elif command_exists bun; then echo "bun"
  else echo ""; fi
}

detect_node() {
  if command_exists node; then node --version; else echo ""; fi
}

detect_os() {
  uname -s 2>/dev/null || echo "unknown"
}

detect_arch() {
  ARCH_NAME=$(uname -m 2>/dev/null || echo "unknown")
  case "$ARCH_NAME" in
    x86_64|amd64) echo "x64" ;;
    arm64|aarch64) echo "arm64" ;;
    *) echo "$ARCH_NAME" ;;
  esac
}

detect_install_mode() {
  OS_NAME=$(detect_os)

  case "$OS_NAME" in
    Darwin)
      echo "desktop"
      return 0
      ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT)
      echo "desktop"
      return 0
      ;;
  esac

  if [ -n "$THREATCRUSH_INSTALL_MODE" ]; then
    echo "$THREATCRUSH_INSTALL_MODE"
    return 0
  fi

  if [ -n "$DISPLAY" ] || [ -n "$WAYLAND_DISPLAY" ] || [ -n "$XDG_CURRENT_DESKTOP" ] || [ -n "$DESKTOP_SESSION" ]; then
    echo "desktop"
    return 0
  fi

  if [ -n "$SSH_CONNECTION" ] || [ -n "$SSH_CLIENT" ] || [ -n "$SSH_TTY" ]; then
    echo "server"
    return 0
  fi

  echo "server"
}

ensure_config_dir() {
  mkdir -p "$CONFIG_DIR"
}

write_install_config() {
  MODE="$1"
  PM_NAME="$2"
  PLATFORM_KIND="$3"
  ensure_config_dir
  cat > "$CONFIG_PATH" <<EOF
{
  "installMode": "$MODE",
  "packageManager": "$PM_NAME",
  "installMethod": "installer",
  "platformKind": "$PLATFORM_KIND"
}
EOF
}

ensure_mise_path() {
  if command_exists mise; then
    return 0
  fi

  if [ -x "$HOME/.local/bin/mise" ]; then
    PATH="$HOME/.local/bin:$PATH"
    export PATH
  elif [ -x "$HOME/.cargo/bin/mise" ]; then
    PATH="$HOME/.cargo/bin:$PATH"
    export PATH
  fi

  command_exists mise
}

install_mise() {
  say "${YELLOW}→ No supported package manager found. Bootstrapping mise...${RESET}"

  if ! command_exists curl; then
    say "${RED}curl is required to install mise automatically.${RESET}"
    exit 1
  fi

  sh -c "$(curl -fsSL ${MISE_INSTALL_URL})"

  if ! ensure_mise_path; then
    say "${RED}mise installed but was not found on PATH.${RESET}"
    say "${DIM}Try opening a new shell, then re-run:${RESET} threatcrush"
    exit 1
  fi
}

ensure_node_with_mise() {
  if command_exists node && command_exists npm; then
    return 0
  fi

  install_mise

  say "${GREEN}→ Installing Node.js LTS with mise...${RESET}"
  mise use -g node@lts >/dev/null 2>&1 || mise install node@lts >/dev/null 2>&1
  ensure_mise_path

  if ! command_exists node || ! command_exists npm; then
    say "${RED}Failed to install Node.js via mise.${RESET}"
    exit 1
  fi
}

ensure_global_prefix() {
  if ! command_exists npm; then
    return 0
  fi

  PREFIX=$(npm config get prefix 2>/dev/null || echo "")
  case "$PREFIX" in
    "$HOME"/*)
      return 0
      ;;
    /usr/*|/opt/*)
      if ! have_sudo; then
        say "${YELLOW}Global npm installs may require elevated permissions on this machine.${RESET}"
      fi
      ;;
  esac
}

# Can this user write where npm puts global packages?
#
# This is the question that decides whether to elevate, and asking it properly
# matters because the wrong answer is not a harmless extra `sudo`. Checking the
# prefix path against `$HOME` is not enough: npm writes packages under
# <prefix>/lib/node_modules and links executables into <prefix>/bin, either of
# which can be owned by someone else whatever the prefix looks like, and on a
# freshly configured prefix neither directory exists yet -- so the probe walks
# up to the nearest parent that does.
global_prefix_writable() {
  PREFIX=$(npm config get prefix 2>/dev/null || echo "")
  [ -n "$PREFIX" ] || return 1

  for dir in "$PREFIX/lib/node_modules" "$PREFIX/bin"; do
    probe="$dir"
    while [ ! -e "$probe" ] && [ "$probe" != "/" ] && [ "$probe" != "." ]; do
      probe=$(dirname "$probe")
    done
    [ -w "$probe" ] || return 1
  done

  return 0
}

# Install the package globally, elevating only when that is actually required.
#
# The old version elevated whenever `sudo` merely existed on the box, which is
# wrong on any machine using a Node version manager -- mise, nvm, asdf, volta.
# Those put npm behind a shim on the user's PATH and the global prefix inside
# $HOME. `sudo` resets PATH to a safe default, the shim is not on it, and the
# install dies with:
#
#   sudo: 'npm': command not found
#
# which names neither the real cause nor anything the user can act on. And in
# the case where sudo *did* resolve an npm, the package would be installed into
# root's toolchain rather than the one the user actually runs.
#
# So: if the prefix is writable, never elevate -- there is nothing sudo could
# add. Only a genuinely system-owned prefix gets the escalation, and then npm
# is invoked by absolute path so a resolvable binary survives PATH being reset.
npm_global_install() {
  SPEC="$1"
  ATTEMPT_LOG=$(mktemp 2>/dev/null || echo "${TMPDIR:-/tmp}/threatcrush-npm-$$.log")

  if npm_try_install "$SPEC" "$ATTEMPT_LOG"; then
    rm -f "$ATTEMPT_LOG"
    return
  fi

  # A native dependency that has no prebuilt binary for this exact Node version
  # falls through to a source build, and then wants a compiler the machine may
  # not have. That is not a reason to fail the whole install: the native module
  # backs the daemon's local event store, and the scanner itself runs without
  # it. Retrying with --ignore-scripts is what this project's own CI repair
  # rule already does for the same signature.
  if native_build_failed "$ATTEMPT_LOG"; then
    say "${YELLOW}→ A native dependency had no prebuilt binary for $(node --version 2>/dev/null || echo 'this Node') and could not be compiled.${RESET}"
    say "${DIM}  Retrying without build scripts; the CLI works, the daemon's local store will not.${RESET}"
    if npm_try_install "$SPEC --ignore-scripts" "$ATTEMPT_LOG"; then
      rm -f "$ATTEMPT_LOG"
      return
    fi
  fi

  say "${RED}Could not install ${PACKAGE_NAME}. npm said:${RESET}"
  tail -n 40 "$ATTEMPT_LOG" >&2
  rm -f "$ATTEMPT_LOG"
  exit 1
}

# One install attempt, with its output kept rather than discarded.
#
# The output is the point. The previous version sent the unprivileged attempt's
# stderr to /dev/null and then reported whatever the sudo fallback said, so a
# native-build failure surfaced as "sudo: npm: command not found" -- an error
# about the wrong thing entirely, with the real cause nowhere on screen.
npm_try_install() {
  # shellcheck disable=SC2086 -- $1 may carry flags and must word-split.
  SPEC_AND_FLAGS="$1"
  LOG="$2"

  if [ "$(id -u)" -eq 0 ] || global_prefix_writable || ! command_exists sudo; then
    # shellcheck disable=SC2086
    npm i -g $SPEC_AND_FLAGS >"$LOG" 2>&1 || return 1
    cat "$LOG"
    return 0
  fi

  # shellcheck disable=SC2086
  if npm i -g $SPEC_AND_FLAGS >"$LOG" 2>&1; then
    cat "$LOG"
    return 0
  fi

  if native_build_failed "$LOG"; then
    # sudo will not fix a missing compiler; let the caller retry differently.
    return 1
  fi

  say "${YELLOW}→ Global prefix is not writable by $(id -un); retrying with sudo...${RESET}"
  NPM_BIN=$(command -v npm 2>/dev/null || echo npm)
  # shellcheck disable=SC2086
  sudo "$NPM_BIN" i -g $SPEC_AND_FLAGS >"$LOG" 2>&1 || return 1
  cat "$LOG"
  return 0
}

# Did this fail because a native module tried to build from source?
native_build_failed() {
  grep -qiE 'gyp ERR!|node-gyp rebuild|No prebuilt binaries found|not found: make|prebuild-install.*(warn|fail)' "$1" 2>/dev/null
}

# A previous install made with a different package manager leaves its own shim
# behind, and that shim often sorts ahead of npm's on PATH. The install then
# succeeds while the user keeps running the old binary - which reads as "the
# installer says it updated but the version never changes". Clear the strays
# before installing rather than leaving two copies to fight over PATH.
#
# Every probe is guarded: `set -e` is on, and none of this is worth aborting a
# working install for. pnpm in particular refuses to run at all when its global
# bin dir is not already exported, so its failure here is expected and benign.
remove_stale_global_installs() {
  KEEP_PM="$1"
  PACKAGE_NAME="$2"

  if [ "$KEEP_PM" != "pnpm" ] && command_exists pnpm; then
    if pnpm ls -g --depth=0 2>/dev/null | grep -q "$PACKAGE_NAME"; then
      say "${YELLOW}→ Removing an older ${PACKAGE_NAME} installed with pnpm...${RESET}"
      pnpm remove -g "$PACKAGE_NAME" >/dev/null 2>&1 ||
        say "${DIM}  Could not remove it. Run: pnpm remove -g ${PACKAGE_NAME}${RESET}"
    fi
  fi

  if [ "$KEEP_PM" != "yarn" ] && command_exists yarn; then
    if yarn global list 2>/dev/null | grep -q "$PACKAGE_NAME"; then
      say "${YELLOW}→ Removing an older ${PACKAGE_NAME} installed with yarn...${RESET}"
      yarn global remove "$PACKAGE_NAME" >/dev/null 2>&1 ||
        say "${DIM}  Could not remove it. Run: yarn global remove ${PACKAGE_NAME}${RESET}"
    fi
  fi

  if [ "$KEEP_PM" != "bun" ] && command_exists bun; then
    if bun pm ls -g 2>/dev/null | grep -q "$PACKAGE_NAME"; then
      say "${YELLOW}→ Removing an older ${PACKAGE_NAME} installed with bun...${RESET}"
      bun remove -g "$PACKAGE_NAME" >/dev/null 2>&1 ||
        say "${DIM}  Could not remove it. Run: bun remove -g ${PACKAGE_NAME}${RESET}"
    fi
  fi
}

install_global_package() {
  PACKAGE_NAME="$1"
  PM=$(detect_pm)

  # Always an explicit `@latest`. A bare package name lets a package manager
  # reuse what it already resolved: pnpm's global lockfile pins the version it
  # first installed, and npm reuses a satisfying tree, so a reinstall over an
  # old copy can hand back that old copy and report success.
  PACKAGE_SPEC="${PACKAGE_NAME}@latest"

  remove_stale_global_installs "$PM" "$PACKAGE_NAME"

  case "$PM" in
    pnpm)
      say "${GREEN}→ Installing ${PACKAGE_NAME} via pnpm...${RESET}"
      pnpm add -g "$PACKAGE_SPEC"
      ;;
    yarn)
      say "${GREEN}→ Installing ${PACKAGE_NAME} via yarn...${RESET}"
      yarn global add "$PACKAGE_SPEC"
      ;;
    bun)
      say "${GREEN}→ Installing ${PACKAGE_NAME} via bun...${RESET}"
      bun add -g "$PACKAGE_SPEC"
      ;;
    npm)
      say "${GREEN}→ Installing ${PACKAGE_NAME} via npm...${RESET}"
      ensure_global_prefix
      npm_global_install "$PACKAGE_SPEC"
      ;;
    *)
      say "${RED}No supported package manager found even after bootstrapping Node.js.${RESET}"
      exit 1
      ;;
  esac
}

# The version we just put on disk, read from the installed package rather than
# from the registry, so this stays correct offline and on a pinned install.
installed_version() {
  PACKAGE_NAME="$1"

  # The global root belongs to whichever package manager did the install, so
  # ask each one we might have used. Reading only `npm root -g` after a pnpm
  # install returned nothing, which silently disabled the shadow check below.
  for ROOT_CMD in "npm root -g" "pnpm root -g"; do
    PKG_ROOT=$($ROOT_CMD 2>/dev/null) || continue
    [ -n "$PKG_ROOT" ] || continue
    FOUND=$(node -p "require('$PKG_ROOT/$PACKAGE_NAME/package.json').version" 2>/dev/null) || continue
    if [ -n "$FOUND" ]; then
      echo "$FOUND"
      return 0
    fi
  done

  return 1
}

# `command_exists threatcrush` only proves *something* named threatcrush is on
# PATH - not that it is the copy we just installed. Without this check the
# installer prints "installed successfully" next to the old version number and
# the user has no idea why the upgrade did nothing.
# Installing a new CLI replaces files on disk and nothing else. A daemon that is
# already running keeps executing the bundle it was spawned from — even after
# that version's directory is gone — so the new build never takes effect until
# it is restarted, while every install reports success.
refresh_daemon() {
  command_exists threatcrush || return 0

  # A systemd-managed daemon must be restarted through systemd. `threatcrush
  # restart` here would stop the supervised copy and start an unsupervised one
  # in its place, which systemd would know nothing about.
  if command_exists systemctl && [ "$(systemctl is-active threatcrushd.service 2>/dev/null)" = "active" ]; then
    say ""
    say "${YELLOW}! threatcrushd is managed by systemd and is still on the old build.${RESET}"
    say "  ${DIM}Restart it with:${RESET} ${GREEN}sudo systemctl restart threatcrushd${RESET}"
    return 0
  fi

  for PIDFILE in "$HOME/.threatcrush/run/threatcrushd.pid" /var/run/threatcrush/threatcrushd.pid; do
    [ -f "$PIDFILE" ] || continue
    DAEMON_PID=$(cat "$PIDFILE" 2>/dev/null || echo "")
    [ -n "$DAEMON_PID" ] || continue
    kill -0 "$DAEMON_PID" 2>/dev/null || continue

    say ""
    say "${DIM}Restarting threatcrushd onto the new build...${RESET}"
    if threatcrush restart >/dev/null 2>&1; then
      say "${GREEN}✓ threatcrushd restarted.${RESET}"
    else
      say "${YELLOW}! Could not restart threatcrushd — run:${RESET} ${GREEN}threatcrush restart${RESET}"
    fi
    return 0
  done

  return 0
}

warn_if_shadowed() {
  EXPECTED="$1"
  ACTIVE="$2"

  if [ -z "$EXPECTED" ] || [ -z "$ACTIVE" ] || [ "$EXPECTED" = "$ACTIVE" ]; then
    return 0
  fi

  ACTIVE_PATH=$(command -v threatcrush 2>/dev/null || echo "unknown")

  say ""
  say "${YELLOW}⚠ PATH still resolves to an older ThreatCrush.${RESET}"
  say "  ${DIM}Just installed:${RESET} ${EXPECTED}"
  say "  ${DIM}Running from PATH:${RESET} ${ACTIVE}  ${DIM}(${ACTIVE_PATH})${RESET}"
  say ""
  say "  ${DIM}Usually a stale shell hash. Try first:${RESET}"
  say "    ${GREEN}hash -r${RESET}   ${DIM}# or open a new terminal${RESET}"
  say "  ${DIM}If it persists, that path is an older copy - remove it:${RESET}"
  say "    ${GREEN}rm ${ACTIVE_PATH}${RESET}"
}

announce_desktop_bundle() {
  OS_NAME=$(detect_os)
  ARCH=$(detect_arch)

  case "$OS_NAME" in
    Darwin)
      DESKTOP_ASSET="threatcrush-desktop-<version>-${ARCH}.dmg"
      ;;
    Linux)
      DESKTOP_ASSET="threatcrush-desktop-<version>-x86_64.AppImage or -amd64.deb"
      ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT)
      DESKTOP_ASSET="threatcrush-desktop-<version>-x64-setup.exe"
      ;;
    *)
      DESKTOP_ASSET=""
      ;;
  esac

  if [ -n "$DESKTOP_ASSET" ]; then
    say "  ${DIM}Download:${RESET} ${DESKTOP_ASSET}"
    say "  ${DIM}From:${RESET}     ${DESKTOP_RELEASES_URL}"
  else
    say "${YELLOW}Desktop builds are not published for ${OS_NAME}.${RESET}"
  fi
}

NODE_VERSION=$(detect_node)
PM=$(detect_pm)
INSTALL_MODE=$(detect_install_mode)
OS_NAME=$(detect_os)
PLATFORM_KIND="linux-server"

case "$OS_NAME" in
  Darwin)
    PLATFORM_KIND="desktop-client"
    ;;
  MINGW*|MSYS*|CYGWIN*|Windows_NT)
    PLATFORM_KIND="desktop-client"
    ;;
  Linux)
    if [ "$INSTALL_MODE" = "desktop" ]; then
      PLATFORM_KIND="linux-desktop"
    else
      PLATFORM_KIND="linux-server"
    fi
    ;;
  *)
    if [ "$INSTALL_MODE" = "desktop" ]; then
      PLATFORM_KIND="desktop-client"
    fi
    ;;
esac

say "  ${DIM}Node.js:${RESET} ${NODE_VERSION:-not found}"
say "  ${DIM}Package manager:${RESET} ${PM:-not found}"
say "  ${DIM}Install mode:${RESET} ${INSTALL_MODE}"
say "  ${DIM}Platform kind:${RESET} ${PLATFORM_KIND}"
say "  ${DIM}Installer strategy:${RESET} curl | sh → detect server/desktop → bootstrap if needed"
say ""

if [ -z "$NODE_VERSION" ] || [ -z "$PM" ]; then
  ensure_node_with_mise
  NODE_VERSION=$(detect_node)
  PM=$(detect_pm)
  say "  ${DIM}Bootstrapped Node.js:${RESET} ${NODE_VERSION:-unknown}"
  say "  ${DIM}Active package manager:${RESET} ${PM:-unknown}"
  say ""
fi

install_global_package "$PKG_NAME"

if [ "$INSTALL_MODE" = "desktop" ]; then
  say ""
  say "${GREEN}→ Desktop platform detected. The desktop app is a separate download:${RESET}"
  announce_desktop_bundle
fi

write_install_config "$INSTALL_MODE" "$(detect_pm)" "$PLATFORM_KIND"

say ""
if command_exists threatcrush; then
  VERSION=$(threatcrush --version 2>/dev/null || echo "unknown")
  EXPECTED_VERSION=$(installed_version "$PKG_NAME" 2>/dev/null || echo "")
  say "${GREEN}✓ ThreatCrush ${VERSION} installed successfully!${RESET}"
  warn_if_shadowed "$EXPECTED_VERSION" "$VERSION"
  refresh_daemon
  say ""
  say "  ${BOLD}Detected install mode:${RESET} ${INSTALL_MODE}"
  say "  ${BOLD}Platform kind:${RESET} ${PLATFORM_KIND}"
  say "  ${BOLD}Preferred usage:${RESET}"
  say "    ${GREEN}threatcrush${RESET}                  ${DIM}# Setup / help${RESET}"
  say "    ${GREEN}threatcrush init${RESET}             ${DIM}# Auto-detect services and generate config${RESET}"
  say "    ${GREEN}threatcrush monitor${RESET}          ${DIM}# Real-time monitoring${RESET}"
  say "    ${GREEN}threatcrush monitor --tui${RESET}    ${DIM}# Interactive dashboard${RESET}"
  say "    ${GREEN}threatcrush update${RESET}           ${DIM}# Upgrade CLI later using the same blessed path${RESET}"
  say "    ${GREEN}threatcrush remove${RESET}           ${DIM}# Uninstall the installed bundle${RESET}"
  say ""
  say "  ${BOLD}Install model:${RESET}"
  say "    ${DIM}• Primary install:${RESET} curl -fsSL https://threatcrush.com/install.sh | sh"
  say "    ${DIM}• Machine type:${RESET} ${INSTALL_MODE}"
  say "    ${DIM}• Platform kind:${RESET} ${PLATFORM_KIND}"
  say "    ${DIM}• Upgrades later:${RESET} threatcrush update"
  say "    ${DIM}• Bare machines:${RESET} installer can bootstrap Node.js with mise"
  if [ "$INSTALL_MODE" = "desktop" ]; then
    say "    ${DIM}• Desktop:${RESET} CLI installed — the desktop app is an optional separate download"
  else
    say "    ${DIM}• Server:${RESET} CLI only"
  fi
else
  say "${RED}Installation completed but 'threatcrush' was not found on PATH.${RESET}"
  say "${DIM}Try one of these:${RESET}"
  say "  ${GREEN}hash -r${RESET}"
  say "  ${GREEN}exec \$SHELL -l${RESET}"
  say "  ${GREEN}npx @profullstack/threatcrush${RESET}"
fi

say ""
say "  ${DIM}Docs:${RESET}   https://threatcrush.com"
say "  ${DIM}GitHub:${RESET} https://github.com/profullstack/threatcrush"
say "  ${DIM}npm:${RESET}    https://www.npmjs.com/package/@profullstack/threatcrush"
say ""

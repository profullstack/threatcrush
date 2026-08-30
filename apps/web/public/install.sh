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

run_cmd() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif command_exists sudo; then
    sudo "$@"
  else
    "$@"
  fi
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

install_global_package() {
  PACKAGE_NAME="$1"
  PM=$(detect_pm)

  case "$PM" in
    pnpm)
      say "${GREEN}→ Installing ${PACKAGE_NAME} via pnpm...${RESET}"
      pnpm add -g "$PACKAGE_NAME"
      ;;
    yarn)
      say "${GREEN}→ Installing ${PACKAGE_NAME} via yarn...${RESET}"
      yarn global add "$PACKAGE_NAME"
      ;;
    bun)
      say "${GREEN}→ Installing ${PACKAGE_NAME} via bun...${RESET}"
      bun add -g "$PACKAGE_NAME"
      ;;
    npm)
      say "${GREEN}→ Installing ${PACKAGE_NAME} via npm...${RESET}"
      ensure_global_prefix
      if [ "$(id -u)" -eq 0 ]; then
        npm i -g "$PACKAGE_NAME"
      elif command_exists sudo; then
        if npm i -g "$PACKAGE_NAME" 2>/dev/null; then
          :
        else
          run_cmd npm i -g "$PACKAGE_NAME"
        fi
      else
        npm i -g "$PACKAGE_NAME"
      fi
      ;;
    *)
      say "${RED}No supported package manager found even after bootstrapping Node.js.${RESET}"
      exit 1
      ;;
  esac
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
  say "${GREEN}✓ ThreatCrush ${VERSION} installed successfully!${RESET}"
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

#!/bin/sh
set -e

# ThreatCrush installer
# Usage: curl -fsSL https://threatcrush.com/install.sh | sh

BOLD="\033[1m"
GREEN="\033[0;32m"
RED="\033[0;31m"
DIM="\033[2m"
RESET="\033[0m"

echo ""
echo "${GREEN}  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗${RESET}"
echo "${GREEN}  ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝${RESET}"
echo "${GREEN}     ██║   ███████║██████╔╝█████╗  ███████║   ██║   ${RESET}"
echo "${GREEN}     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ${RESET}"
echo "${GREEN}     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ${RESET}"
echo "${GREEN}     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝${RESET}"
echo "${DIM}                    C R U S H${RESET}"
echo ""

# Detect package manager
detect_pm() {
  if command -v pnpm >/dev/null 2>&1; then
    echo "pnpm"
  elif command -v yarn >/dev/null 2>&1; then
    echo "yarn"
  elif command -v npm >/dev/null 2>&1; then
    echo "npm"
  elif command -v bun >/dev/null 2>&1; then
    echo "bun"
  else
    echo ""
  fi
}

# Detect if Node.js is installed
detect_node() {
  if command -v node >/dev/null 2>&1; then
    node --version
  else
    echo ""
  fi
}

NODE_VERSION=$(detect_node)
PM=$(detect_pm)

# If no Node.js, install via nvm or suggest install
if [ -z "$NODE_VERSION" ]; then
  echo "${RED}Node.js not found.${RESET}"
  echo ""
  echo "Install Node.js first:"
  echo "  ${GREEN}curl -fsSL https://fnm.vercel.app/install | bash${RESET}"
  echo "  ${GREEN}fnm install --lts${RESET}"
  echo ""
  echo "Or visit: https://nodejs.org"
  echo ""
  exit 1
fi

echo "  ${DIM}Node.js:${RESET} $NODE_VERSION"
echo "  ${DIM}Package manager:${RESET} $PM"
echo ""

# Install via detected package manager
case "$PM" in
  pnpm)
    echo "${GREEN}→ Installing via pnpm...${RESET}"
    pnpm add -g @profullstack/threatcrush
    ;;
  yarn)
    echo "${GREEN}→ Installing via yarn...${RESET}"
    yarn global add @profullstack/threatcrush
    ;;
  bun)
    echo "${GREEN}→ Installing via bun...${RESET}"
    bun add -g @profullstack/threatcrush
    ;;
  npm)
    echo "${GREEN}→ Installing via npm...${RESET}"
    npm i -g @profullstack/threatcrush
    ;;
  *)
    echo "${RED}No package manager found (npm, pnpm, yarn, bun).${RESET}"
    echo "Install one first, then run:"
    echo "  ${GREEN}npm i -g @profullstack/threatcrush${RESET}"
    exit 1
    ;;
esac

echo ""

# Verify installation
if command -v threatcrush >/dev/null 2>&1; then
  VERSION=$(threatcrush --version 2>/dev/null || echo "unknown")
  echo "${GREEN}✓ ThreatCrush v${VERSION} installed successfully!${RESET}"
  echo ""
  echo "  Get started:"
  echo "    ${GREEN}threatcrush${RESET}          ${DIM}# Setup & join waitlist${RESET}"
  echo "    ${GREEN}threatcrush monitor${RESET}  ${DIM}# Real-time security monitoring${RESET}"
  echo "    ${GREEN}threatcrush tui${RESET}      ${DIM}# Interactive dashboard${RESET}"
  echo "    ${GREEN}threatcrush scan .${RESET}   ${DIM}# Scan code for vulnerabilities${RESET}"
  echo ""
  echo "  ${DIM}Docs:${RESET}   https://threatcrush.com"
  echo "  ${DIM}GitHub:${RESET} https://github.com/profullstack/threatcrush"
  echo "  ${DIM}npm:${RESET}    https://www.npmjs.com/package/@profullstack/threatcrush"
else
  echo "${RED}Installation completed but 'threatcrush' command not found in PATH.${RESET}"
  echo "Try running: ${GREEN}npx @profullstack/threatcrush${RESET}"
fi

echo ""

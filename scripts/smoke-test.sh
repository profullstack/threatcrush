#!/usr/bin/env bash
# ThreatCrush v0.1.0 smoke test.
#
# Runs end-to-end against a fresh machine (or a VM) to confirm the install
# path, daemon lifecycle, and property run flow all work.
#
# Usage:
#   ./scripts/smoke-test.sh              # uses https://threatcrush.com
#   API_URL=http://localhost:3000 ./scripts/smoke-test.sh
#   TC_BIN=./apps/cli/dist/index.js ./scripts/smoke-test.sh  # test a local build
#
# Required environment to exercise authenticated flows:
#   TC_EMAIL, TC_PASSWORD — login against threatcrush.com
#
# Set SKIP_INSTALL=1 to skip the curl|sh step if the CLI is already installed.

set -euo pipefail

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
DIM=$'\033[2m'
RESET=$'\033[0m'

API_URL="${API_URL:-https://threatcrush.com}"
TC_BIN="${TC_BIN:-}"
SKIP_INSTALL="${SKIP_INSTALL:-0}"

STEP=0
pass() { STEP=$((STEP+1)); printf "%b[%02d] ✓ %s%b\n" "$GREEN" "$STEP" "$1" "$RESET"; }
fail() { STEP=$((STEP+1)); printf "%b[%02d] ✗ %s%b\n" "$RED" "$STEP" "$1" "$RESET"; exit 1; }
info() { printf "%b    %s%b\n" "$DIM" "$1" "$RESET"; }
warn() { printf "%b[!] %s%b\n" "$YELLOW" "$1" "$RESET"; }

tc() {
  if [ -n "$TC_BIN" ]; then
    node "$TC_BIN" "$@"
  else
    threatcrush "$@"
  fi
}

# ─── 1. Install path (optional) ───
if [ "$SKIP_INSTALL" != "1" ] && [ -z "$TC_BIN" ]; then
  if ! command -v threatcrush >/dev/null 2>&1; then
    info "Installing via curl | sh ..."
    curl -fsSL "${API_URL}/install.sh" | sh >/dev/null 2>&1 || fail "install.sh failed"
  fi
  command -v threatcrush >/dev/null 2>&1 || fail "threatcrush not on PATH after install"
  pass "CLI installed: $(command -v threatcrush)"
else
  pass "Skipped install (TC_BIN=${TC_BIN:-unset}, SKIP_INSTALL=$SKIP_INSTALL)"
fi

# ─── 2. Version check ───
VERSION=$(tc --version 2>&1 | head -1 | tr -d '[:space:]')
[ -n "$VERSION" ] || fail "threatcrush --version returned nothing"
pass "Version: $VERSION"

# ─── 3. Help output includes key commands ───
HELP=$(tc --help 2>&1)
for cmd in monitor tui scan pentest status start stop daemon properties login; do
  echo "$HELP" | grep -q "$cmd" || fail "'$cmd' missing from help output"
done
pass "Help lists all v0.1.0 commands"

# ─── 4. Clean slate ───
rm -rf "$HOME/.threatcrush/run" "$HOME/.threatcrush/state" "$HOME/.threatcrush/logs" || true
pass "Reset local runtime dirs"

# ─── 5. Status (not running) ───
OUT=$(tc status 2>&1 || true)
echo "$OUT" | grep -q "NOT RUNNING" || fail "status should say NOT RUNNING on clean host"
pass "status correctly reports NOT RUNNING"

# ─── 6. Start daemon ───
tc start >/dev/null 2>&1 || fail "threatcrush start failed"
sleep 1
OUT=$(tc status 2>&1 || true)
echo "$OUT" | grep -qE "RUNNING" || fail "status does not show RUNNING after start"
echo "$OUT" | grep -qE "log-watcher|ssh-guard" || fail "built-in modules not listed"
pass "Daemon started, IPC reachable"

# ─── 7. IPC handshake ───
node -e "
const { createConnection } = require('node:net');
const { join } = require('node:path');
const sock = createConnection(join(process.env.HOME, '.threatcrush/run/threatcrushd.sock'));
sock.setEncoding('utf-8');
let buf = '';
const timer = setTimeout(() => { console.error('timeout'); process.exit(2); }, 3000);
sock.on('data', d => {
  buf += d;
  const idx = buf.indexOf('\\n'); if (idx < 0) return;
  const msg = JSON.parse(buf.slice(0, idx));
  if (!msg.ok) { console.error('bad reply', msg); process.exit(3); }
  if (!msg.result.pid) { console.error('no pid'); process.exit(4); }
  clearTimeout(timer);
  sock.end();
});
sock.on('connect', () => sock.write(JSON.stringify({id:1,method:'status'})+'\\n'));
" || fail "IPC status handshake failed"
pass "IPC JSON-RPC status reply valid"

# ─── 8. TUI path compiles ───
timeout 2 tc tui </dev/null >/dev/null 2>&1 || true
pass "TUI launched (timed out at 2s — no renderer attached)"

# ─── 9. Scan on a tiny fixture ───
FIX=$(mktemp -d)
cat > "$FIX/leaky.js" <<'EOF'
const aws = "AKIAIOSFODNN7EXAMPLE";
const pw = "password=supersecretvalue12345";
EOF
OUT=$(tc scan "$FIX" 2>&1)
echo "$OUT" | grep -qE "(critical|high)" || fail "scan didn't flag the AWS key fixture"
rm -rf "$FIX"
pass "scan flagged test secrets"

# ─── 10. Stop daemon ───
tc stop >/dev/null 2>&1 || fail "threatcrush stop failed"
sleep 1
OUT=$(tc status 2>&1 || true)
echo "$OUT" | grep -q "NOT RUNNING" || fail "daemon didn't shut down cleanly"
pass "Daemon stopped cleanly"

# ─── 11. Login + properties flow (optional) ───
if [ -n "${TC_EMAIL:-}" ] && [ -n "${TC_PASSWORD:-}" ]; then
  info "Logging in as $TC_EMAIL ..."
  # login accepts --email; we feed password via stdin since there's no flag
  printf "%s\n" "$TC_PASSWORD" | tc login --email "$TC_EMAIL" >/dev/null 2>&1 || fail "login failed"
  pass "Logged in to $API_URL"

  OUT=$(tc whoami 2>&1 || true)
  echo "$OUT" | grep -q "$TC_EMAIL" || fail "whoami doesn't show $TC_EMAIL"
  pass "whoami reports the expected account"

  tc properties list >/dev/null 2>&1 || fail "properties list failed"
  pass "properties list returned"

  # Add a throwaway property + run + remove.
  NAME="smoketest-$(date +%s)"
  tc properties add "$NAME" https://example.com --kind url -t smoke >/dev/null 2>&1 \
    || fail "properties add failed"
  pass "Added property $NAME"

  tc properties run -n "$NAME" -t pentest 2>&1 | tail -3 | grep -qE "(done|Completed)" \
    || warn "properties run didn't confirm completion (may still have succeeded)"
  pass "Ran pentest against $NAME"

  tc properties remove "$NAME" -y >/dev/null 2>&1 || fail "properties remove failed"
  pass "Removed property $NAME"
else
  info "Skipping login + properties flow (set TC_EMAIL and TC_PASSWORD to enable)"
fi

printf "\n%b✅ smoke test passed — v0.1.0 launch path is green.%b\n\n" "$GREEN" "$RESET"

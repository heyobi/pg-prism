#!/usr/bin/env bash
#
# Make the client-address gap visible on a single machine.
#
# `smoke-native.sh` proves the mechanism but not the point: everything is on
# loopback there, so `pg_stat_activity` shows 127.0.0.1 in both the injected
# suffix and `client_addr`, and a screenshot of it demonstrates nothing.
#
# This binds HAProxy to the WSL interface instead. A client connecting to that
# address is genuinely off-box from PostgreSQL's point of view, so the two
# columns disagree — which is the entire argument of the talk in one row:
#
#     application_name          | client_addr
#     --------------------------+-------------
#     gap-demo - 172.21.35.33   | 127.0.0.1
#
# Stronger still, connect from Windows to the same address and PG-Prism logs
# the Windows host address across the virtual switch (172.21.32.1 here).
#
# Note that TRUSTED_PROXIES does not need changing. HAProxy still reaches
# PG-Prism over loopback; only its *frontend* moves to the interface. Moving
# HAProxy off-box would be a different matter and would need the allowlist
# widened.
#
# ---------------------------------------------------------------------------
# Three things that went wrong the first time this was rehearsed. All three are
# handled below; they are written down because they will happen again on a
# conference machine at nine in the morning.
#
#   1. Backgrounding with a bare `&` is not enough. When the invoking shell
#      exits, PG-Prism dies with it, HAProxy stays up, and the demo fails with
#      a connection error that looks like a bug in the proxy. Needs nohup and
#      disown.
#
#   2. A stale HAProxy from an earlier run keeps holding the port and happily
#      answers with a dead backend. The symptom is identical to (1). Kill any
#      previous instance by config path before starting.
#
#   3. The smoke-test role password is prism_smoke_pw, not prism_smoke. Getting
#      it wrong produces a password-authentication failure that reads like a
#      PG-Prism problem and is not.
# ---------------------------------------------------------------------------
#
# Usage:  scripts/gap-demo.sh          # start, connect once, leave running
#         scripts/gap-demo.sh --stop   # tear down
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRISM_PORT=6433
HAPROXY_PORT=6434
DB_USER=prism_smoke
DB_PASS=prism_smoke_pw
DB_NAME=prism_smoke
PG_PORT=5432

HAPROXY_CFG=/tmp/gap-haproxy.cfg
PRISM_LOG=/tmp/gap-prism.log

bold() { printf '\033[1;36m==> %s\033[0m\n' "$1"; }
ok()   { printf '\033[1;32m  OK\033[0m %s\n' "$1"; }
note() { printf '\033[1;33m  NOTE\033[0m %s\n' "$1"; }

stop_everything() {
    # Trap 2: match on the config path, not the process name, so this cannot
    # take out an unrelated HAProxy the machine is running for something else.
    pkill -f "haproxy -f $HAPROXY_CFG" >/dev/null 2>&1 || true
    pkill -f 'pg-prism-rust' >/dev/null 2>&1 || true
    sleep 1
}

if [[ "${1:-}" == "--stop" ]]; then
    bold "Tearing down"
    stop_everything
    ok "stopped"
    exit 0
fi

WSL_IP=$(hostname -I | awk '{print $1}')
if [[ -z "$WSL_IP" ]]; then
    echo "Could not determine an interface address from 'hostname -I'." >&2
    exit 1
fi
bold "Interface address: $WSL_IP"

bold "Clearing anything left over from a previous run"
stop_everything
ok "clear"

bold "Building PG-Prism"
# rustup installs cargo into ~/.cargo/bin via a line in ~/.profile, which a
# non-interactive shell does not always read. Found the hard way.
command -v cargo >/dev/null 2>&1 || . "$HOME/.cargo/env" 2>/dev/null || true
command -v cargo >/dev/null 2>&1 || { echo "cargo is not on PATH and ~/.cargo/env did not help"; exit 1; }
# Errors are shown, not swallowed: a build failure here otherwise looks
# identical to every other way this script can fail.
cargo build --release --locked --manifest-path "$REPO_ROOT/core/rust/Cargo.toml" || {
    echo "build failed, see above"; exit 1; }
ok "built"

cat > "$HAPROXY_CFG" <<CFG
global
    log stdout format raw local0
defaults
    log     global
    mode    tcp
    timeout connect 10s
    timeout client  5m
    timeout server  5m
frontend pg_in
    # The whole point: bind the interface, not loopback.
    bind ${WSL_IP}:${HAPROXY_PORT}
    default_backend prism
backend prism
    server p 127.0.0.1:${PRISM_PORT} send-proxy
CFG

bold "Starting PG-Prism on ${PRISM_PORT}"
cd "$REPO_ROOT/core/rust"
# Trap 1: nohup + disown, or this dies with the invoking shell.
LISTEN_HOST=127.0.0.1 LISTEN_PORT=$PRISM_PORT \
PG_HOST=127.0.0.1 PG_PORT=$PG_PORT \
SSL_ENABLED=false RUST_LOG=info \
    nohup ./target/release/pg-prism-rust > "$PRISM_LOG" 2>&1 &
disown
sleep 2
grep -q 'PG-Prism running' "$PRISM_LOG" || { echo "PG-Prism did not start:"; cat "$PRISM_LOG"; exit 1; }
ok "listening"

bold "Starting HAProxy on ${WSL_IP}:${HAPROXY_PORT}"
haproxy -f "$HAPROXY_CFG" -D || { echo "haproxy failed to start"; exit 1; }
sleep 2
ok "listening"

bold "Connecting from ${WSL_IP}"
# Trap 3: the password is prism_smoke_pw.
PGPASSWORD="$DB_PASS" PGAPPNAME=gap-demo \
    psql -h "$WSL_IP" -p "$HAPROXY_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -c "SELECT application_name, client_addr FROM pg_stat_activity WHERE pid = pg_backend_pid();"

bold "What PG-Prism read out of the PROXY header"
grep 'Real Client IP' "$PRISM_LOG" | tail -3

echo
note "The two columns above should differ. If both say 127.0.0.1 you connected"
note "over loopback instead of ${WSL_IP}."
echo
note "For a second, larger gap: from Windows, connect to ${WSL_IP}:${HAPROXY_PORT}"
note "and watch $PRISM_LOG. The address will be the Windows side of the"
note "virtual switch, which is a different machine as far as PostgreSQL knows."
echo
note "Still running. Tear down with: scripts/gap-demo.sh --stop"

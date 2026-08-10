#!/usr/bin/env bash
#
# Same proof as smoke.sh, over a native WSL2/Linux stack with no containers:
# PostgreSQL and HAProxy from apt, PG-Prism built with cargo.
#
# This is the path the conference demo depends on, because the demo laptop does
# not have the disk for Docker. smoke.sh stays in the repo for everyone else.
#
# Usage:
#   ./scripts/smoke-native.sh            # set up, test, tear down
#   KEEP=1 ./scripts/smoke-native.sh     # leave HAProxy and PG-Prism running
#
# Requires: postgresql, postgresql-client, haproxy, and a Rust toolchain.
# See docs/DEV_ENVIRONMENT.md section 3 for the apt line.

set -euo pipefail

cd "$(dirname "$0")/.."
REPO="$PWD"

# Ports chosen to avoid clashing with anything already installed.
PG_PORT="${PG_PORT:-5432}"
PRISM_PORT="${PRISM_PORT:-6433}"
HAPROXY_PORT="${HAPROXY_PORT:-6434}"

APP_NAME="smoke-test"
DB_USER="prism_smoke"
DB_PASS="prism_smoke_pw"
DB_NAME="prism_smoke"

RUNDIR="$(mktemp -d /tmp/pg-prism-smoke.XXXXXX)"
PRISM_LOG="$RUNDIR/prism.log"
HAPROXY_LOG="$RUNDIR/haproxy.log"
PRISM_PID=""
HAPROXY_PID=""

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  OK\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m  NOTE\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m  FAIL\033[0m %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [ "${KEEP:-0}" = "1" ]; then
    log "KEEP=1. Still running:"
    printf '  PG-Prism  pid %s  log %s\n' "${PRISM_PID:-none}" "$PRISM_LOG"
    printf '  HAProxy   pid %s  log %s\n' "${HAPROXY_PID:-none}" "$HAPROXY_LOG"
    printf '  psql -h 127.0.0.1 -p %s -U %s %s\n' "$HAPROXY_PORT" "$DB_USER" "$DB_NAME"
    return
  fi
  log "Tearing down"
  [ -n "$HAPROXY_PID" ] && kill "$HAPROXY_PID" 2>/dev/null || true
  [ -n "$PRISM_PID" ] && kill "$PRISM_PID" 2>/dev/null || true
  rm -rf "$RUNDIR"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------

log "Checking prerequisites"
for bin in psql haproxy cargo; do
  command -v "$bin" >/dev/null || fail "$bin is not on PATH. See docs/DEV_ENVIRONMENT.md"
done
ok "psql $(psql --version | awk '{print $3}'), haproxy present, cargo $(cargo --version | awk '{print $2}')"

if ! pg_isready -h 127.0.0.1 -p "$PG_PORT" >/dev/null 2>&1; then
  warn "PostgreSQL is not accepting connections on 127.0.0.1:$PG_PORT"
  warn "Start it with: sudo pg_ctlcluster \$(pg_lsclusters -h | awk 'NR==1{print \$1}') main start"
  fail "PostgreSQL is not running"
fi
ok "PostgreSQL is up on $PG_PORT"

# ---------------------------------------------------------------------------

setup_role() {
  sudo -u postgres psql -p "$PG_PORT" -v ON_ERROR_STOP=1 -q <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$DB_USER') THEN
    CREATE ROLE $DB_USER LOGIN PASSWORD '$DB_PASS';
  ELSE
    ALTER ROLE $DB_USER LOGIN PASSWORD '$DB_PASS';
  END IF;
END
\$\$;
SQL
  local exists
  exists=$(sudo -u postgres psql -p "$PG_PORT" -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'")
  if [ "$exists" != "1" ]; then
    sudo -u postgres createdb -p "$PG_PORT" -O "$DB_USER" "$DB_NAME"
  fi
  ok "role and database ready"
}

# Only touch the cluster when we have to. A repeat run, and the demo rehearsal
# in particular, must not stop for a sudo password prompt.
if PGPASSWORD="$DB_PASS" psql -h 127.0.0.1 -p "$PG_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc 'SELECT 1' >/dev/null 2>&1; then
  log "Smoke-test role and database already present"
  ok "reusing $DB_USER@$DB_NAME, no sudo needed"
else
  log "Creating the smoke-test role and database"
  warn "this step needs sudo; later runs skip it"
  setup_role
fi

# ---------------------------------------------------------------------------

log "Building PG-Prism"
cargo build --release --locked --manifest-path core/rust/Cargo.toml 2>&1 | tail -2
BIN="$REPO/core/rust/target/release/pg-prism-rust"
[ -x "$BIN" ] || fail "the binary was not produced at $BIN"
ok "built"

log "Starting PG-Prism on $PRISM_PORT"
# Everything is on loopback here, so the default TRUSTED_PROXIES is correct and
# is deliberately left unset: if the default ever stops covering loopback this
# script should notice.
#
# SSL is off because the proxy would shell out to openssl and mint a
# certificate in the working directory. TLS has its own coverage in CI.
(
  cd "$RUNDIR"
  LISTEN_HOST=127.0.0.1 \
  LISTEN_PORT="$PRISM_PORT" \
  PG_HOST=127.0.0.1 \
  PG_PORT="$PG_PORT" \
  SSL_ENABLED=false \
  RUST_LOG=info \
  "$BIN" >"$PRISM_LOG" 2>&1 &
  echo $! > "$RUNDIR/prism.pid"
)
PRISM_PID="$(cat "$RUNDIR/prism.pid")"

for i in $(seq 1 30); do
  grep -q "PG-Prism running on" "$PRISM_LOG" 2>/dev/null && break
  kill -0 "$PRISM_PID" 2>/dev/null || { cat "$PRISM_LOG"; fail "PG-Prism exited on startup"; }
  [ "$i" = "30" ] && { cat "$PRISM_LOG"; fail "PG-Prism never reported that it was listening"; }
  sleep 0.5
done
ok "PG-Prism is listening (pid $PRISM_PID)"

log "Trusted proxy configuration as the proxy sees it"
grep "Accepting PROXY headers only from" "$PRISM_LOG" \
  || fail "the proxy did not log its allowlist; is this an older build?"

# ---------------------------------------------------------------------------

log "Starting HAProxy on $HAPROXY_PORT"
cat > "$RUNDIR/haproxy.cfg" <<CFG
global
    log stdout format raw local0
    maxconn 256

defaults
    log     global
    mode    tcp
    timeout connect 5s
    timeout client  1m
    timeout server  1m

frontend postgres_in
    bind 127.0.0.1:$HAPROXY_PORT
    default_backend pg_prism_backend

backend pg_prism_backend
    server pg_prism 127.0.0.1:$PRISM_PORT check send-proxy
CFG

haproxy -f "$RUNDIR/haproxy.cfg" -D -p "$RUNDIR/haproxy.pid" 2>"$HAPROXY_LOG" \
  || { cat "$HAPROXY_LOG"; fail "HAProxy did not start"; }
HAPROXY_PID="$(cat "$RUNDIR/haproxy.pid")"
ok "HAProxy is listening (pid $HAPROXY_PID)"

# ---------------------------------------------------------------------------
# The path under test:
#   psql -> 127.0.0.1:$HAPROXY_PORT -> (PROXY header) -> :$PRISM_PORT -> :$PG_PORT
#
# PGAPPNAME puts application_name in the StartupMessage, which is where the
# proxy injects. Deliberately not `SET application_name`: the proxy does not
# rewrite statements, so a SET would overwrite the injected value and this
# script would be testing nothing.
# ---------------------------------------------------------------------------

log "Connecting through HAProxy -> PG-Prism -> PostgreSQL"
set +e
OUTPUT=$(PGPASSWORD="$DB_PASS" PGAPPNAME="$APP_NAME" \
  psql -h 127.0.0.1 -p "$HAPROXY_PORT" -U "$DB_USER" -d "$DB_NAME" \
       -v ON_ERROR_STOP=1 -At \
       -c "SELECT application_name, client_addr FROM pg_stat_activity WHERE pid = pg_backend_pid()" 2>&1)
STATUS=$?
set -e

if [ $STATUS -ne 0 ]; then
  printf '%s\n' "$OUTPUT" >&2
  log "PG-Prism log"
  tail -30 "$PRISM_LOG" >&2
  fail "the connection through the proxy failed"
fi

log "pg_stat_activity row"
printf '  %s\n' "$OUTPUT"

APP_SEEN="${OUTPUT%%|*}"
ADDR_SEEN="${OUTPUT##*|}"

if ! printf '%s' "$APP_SEEN" | grep -qE '^'"$APP_NAME"' - [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
  fail "application_name is '$APP_SEEN', expected '$APP_NAME - <client address>'.
       The PROXY header was not applied. Compare the allowlist line above with
       the address HAProxy connects from."
fi
ok "application_name carries the client address: $APP_SEEN"

# On a native single-host stack everything is loopback, so client_addr is
# 127.0.0.1 and so is the recovered address. The demo makes the gap visible by
# connecting from a second machine or a WSL bridge address; here we only prove
# the mechanism works.
warn "client_addr is $ADDR_SEEN. On a single host both sides are loopback, so"
printf '       this does not show the gap. It shows the mechanism. Use a second\n'
printf '       host, or a non-loopback interface, to demonstrate the difference.\n'

log "Smoke test passed"

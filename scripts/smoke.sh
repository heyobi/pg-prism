#!/usr/bin/env bash
#
# Brings up the compose stack, pushes one connection through HAProxy and
# PG-Prism into PostgreSQL, prints the resulting pg_stat_activity row, and tears
# everything down.
#
# This is the five-minute answer to "does the thing actually work". It is also
# the check that the trusted-proxy allowlist added in A2 did not break the
# deployment that used to work: HAProxy runs in its own container here, so it is
# not on loopback, and the stack has to name its subnet in TRUSTED_PROXIES.
#
# Usage:
#   ./scripts/smoke.sh           # up, test, down
#   KEEP=1 ./scripts/smoke.sh    # leave the stack running afterwards
#
# Requires: docker with the compose plugin. Nothing else; psql runs inside the
# postgres container so you do not need client tools on the host.

set -euo pipefail

cd "$(dirname "$0")/.."

APP_NAME="smoke-test"
PGPASSWORD_VALUE="test123"

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  OK\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m  FAIL\033[0m %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [ "${KEEP:-0}" = "1" ]; then
    log "KEEP=1, leaving the stack up. Tear down with: docker compose down -v"
    return
  fi
  log "Tearing down"
  docker compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------

command -v docker >/dev/null || fail "docker is not on PATH. See docs/DEV_ENVIRONMENT.md"
docker compose version >/dev/null 2>&1 || fail "the docker compose plugin is missing. See docs/DEV_ENVIRONMENT.md"

log "Building and starting the stack"
docker compose up -d --build

log "Waiting for PostgreSQL"
for i in $(seq 1 60); do
  if docker compose exec -T postgres pg_isready -U postgres >/dev/null 2>&1; then
    ok "PostgreSQL is accepting connections"
    break
  fi
  [ "$i" = "60" ] && fail "PostgreSQL did not become ready within 60s"
  sleep 1
done

log "Waiting for PG-Prism to bind its listener"
for i in $(seq 1 30); do
  if docker compose logs pg-prism 2>/dev/null | grep -q "PG-Prism running on"; then
    ok "PG-Prism is listening"
    break
  fi
  [ "$i" = "30" ] && {
    docker compose logs pg-prism
    fail "PG-Prism never reported that it was listening"
  }
  sleep 1
done

# The allowlist is the thing most likely to be misconfigured, so show what the
# proxy actually decided rather than making the reader infer it from a failure.
log "Trusted proxy configuration as the proxy sees it"
docker compose logs pg-prism | grep "Accepting PROXY headers only from" || \
  fail "the proxy did not log its allowlist; is this an older build?"

# ---------------------------------------------------------------------------
# The actual test. psql runs inside the postgres container and connects out to
# HAProxy by service name, so the path is:
#
#   psql -> haproxy:5434 -> (PROXY header) -> pg-prism:5433 -> postgres:5432
#
# HAProxy is a different container, so the address PG-Prism sees is the compose
# network address, which is why docker-compose.yml sets TRUSTED_PROXIES.
# ---------------------------------------------------------------------------

# PGAPPNAME puts application_name in the StartupMessage, which is where the
# proxy injects. Deliberately not `SET application_name`: the proxy does not
# rewrite statements, so a SET would simply overwrite the injected value and
# this script would be testing nothing.
log "Connecting through HAProxy -> PG-Prism -> PostgreSQL"
set +e
OUTPUT=$(docker compose exec -T \
  -e PGPASSWORD="$PGPASSWORD_VALUE" \
  -e PGAPPNAME="$APP_NAME" \
  postgres \
  psql -h haproxy -p 5434 -U postgres -d postgres \
       -v ON_ERROR_STOP=1 -At \
       -c "SELECT application_name, client_addr FROM pg_stat_activity WHERE pid = pg_backend_pid()" 2>&1)
STATUS=$?
set -e

if [ $STATUS -ne 0 ]; then
  printf '%s\n' "$OUTPUT" >&2
  log "PG-Prism logs"
  docker compose logs --tail=40 pg-prism >&2
  fail "the connection through the proxy failed"
fi

log "pg_stat_activity row"
printf '  %s\n' "$OUTPUT"

# ---------------------------------------------------------------------------

APP_SEEN="${OUTPUT%%|*}"
ADDR_SEEN="${OUTPUT##*|}"

# The client here is psql inside the postgres container, so the address the
# PROXY header carries is that container's address on the compose network. The
# specific value does not matter; what matters is that an address appears at
# all, and that it is not the one PostgreSQL would have seen by itself.
if ! printf '%s' "$APP_SEEN" | grep -qE '^'"$APP_NAME"' - [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
  fail "application_name is '$APP_SEEN', expected '$APP_NAME - <client address>'.
       The PROXY header was not applied. Most likely TRUSTED_PROXIES in
       docker-compose.yml does not cover the compose network subnet; compare it
       with the 'Accepting PROXY headers only from' line logged above."
fi
ok "application_name carries the real client address: $APP_SEEN"

INJECTED_ADDR="${APP_SEEN##* - }"
if [ "$INJECTED_ADDR" = "$ADDR_SEEN" ]; then
  printf '\033[1;33m  NOTE\033[0m client_addr and the injected address match (%s).\n' "$ADDR_SEEN"
  printf '       In this stack PostgreSQL sees PG-Prism, and PG-Prism runs in a\n'
  printf '       separate container from HAProxy, so the two can coincide. On a\n'
  printf '       real sidecar deployment client_addr would be 127.0.0.1.\n'
else
  ok "PostgreSQL saw the connection as coming from $ADDR_SEEN, but the real"
  printf '       client %s was recovered from the PROXY header. That gap is\n' "$INJECTED_ADDR"
  printf '       the entire point of the project.\n'
fi

log "Smoke test passed"

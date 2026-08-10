# Development environment

The Rust core builds and its fast test suite runs anywhere Rust does, including
Windows with no other tooling. CI covers the real-PostgreSQL tests on Linux, so
you do not need containers to develop or to have the protocol tests run.

Beyond that there are **two supported paths**, and they are not equivalent:

| Path | What it needs | Who it is for |
| :--- | :--- | :--- |
| **Native (section 2)** | WSL2 + Ubuntu, PostgreSQL and HAProxy from apt, `cargo` | **The conference demo depends on this one.** No Docker, ~1.5 GB. |
| Containers (section 6) | Docker Desktop + compose | Everyone else, and anyone reproducing the published setup. |

The native path exists because the demo laptop does not have the disk for
Docker. It is the one that gets rehearsed and the one that has to work offline
on the day. The compose path stays in the repository because it is what most
readers will try first, but it is not on the critical path for the talk.

| Deliverable | Native | Containers |
| :--- | :--- | :--- |
| `scripts/smoke-native.sh` | ✅ | — |
| `scripts/smoke.sh` | — | ✅ |
| The conference demo | ✅ **primary** | fallback only |
| The benchmark (`bench/`) | ✅ | ✅ |

---

## 1. What works with no setup

```bash
cd core/rust
cargo build --locked
cargo test --locked          # unit tests + the fake-backend integration suite
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
```

The `#[ignore]`d tests in `tests/real_postgres.rs` are skipped here. They run in
CI against a `postgres:16` service container. If you want them locally, point
them at any reachable server:

```bash
PGHOST=127.0.0.1 PGPORT=5432 PGUSER=postgres PGPASSWORD=secret \
  cargo test --test real_postgres -- --include-ignored --test-threads=1
```

---

## 2. Native path: WSL2 with everything from apt

### Disk budget

| Item | Size |
| :--- | :--- |
| WSL2 kernel + Ubuntu | ~1.2 GB |
| `postgresql` + `postgresql-client` | ~180 MB |
| `haproxy` | ~5 MB |
| Rust toolchain (if not already in WSL) | ~1.3 GB |
| `target/` after a release build | ~400 MB |

**Budget 3.5 GB**, or ~2.2 GB if you build on Windows and only run the stack in
WSL. Compare with section 6: the container path needs about 8 GB.

### Install WSL2

Run in an **Administrator** PowerShell:

```powershell
wsl --install -d Ubuntu
```

This enables the Virtual Machine Platform and WSL features, installs the WSL2
kernel and Ubuntu, and sets WSL2 as the default. It requires a reboot. On some
machines virtualisation must be enabled in firmware first (Intel VT-x or AMD-V);
if `wsl --install` says so, change it in the BIOS/UEFI and retry.

After rebooting, Ubuntu asks for a username and password. Then:

```powershell
wsl --set-default-version 2
wsl -l -v          # Ubuntu should show VERSION 2
```

### Install the stack

Everything below runs **inside WSL**.

```bash
sudo apt-get update
sudo apt-get install -y postgresql postgresql-client haproxy build-essential pkg-config libssl-dev

# Rust, if it is not already there
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

`libssl-dev` and `pkg-config` are needed because `native-tls` links OpenSSL on
Linux.

### Start PostgreSQL

WSL images often ship without systemd, so use the `service` wrapper:

```bash
sudo service postgresql start
pg_isready -h 127.0.0.1 -p 5432
```

If `pg_isready` reports no connection, PostgreSQL may be listening only on its
Unix socket. Check `listen_addresses`:

```bash
sudo -u postgres psql -tAc "SHOW listen_addresses"     # want 'localhost' or '*'
```

The proxy connects over TCP, so this has to include localhost. Ubuntu's default
already does.

### Clone and run

Clone **inside** the WSL filesystem, not under `/mnt/c`. Files on the Windows
mount are far slower, which matters for the benchmark and is noticeable even
when building.

```bash
git clone https://github.com/heyobi/pg-prism.git ~/pg-prism
cd ~/pg-prism
./scripts/smoke-native.sh
```

The script checks its prerequisites, creates a throwaway role and database,
builds the proxy, starts PG-Prism on 6433 and HAProxy on 6434, sends one
connection along the full path, prints the `pg_stat_activity` row, and stops
what it started. `KEEP=1 ./scripts/smoke-native.sh` leaves the proxy and HAProxy
running so you can poke at them.

A pass looks like:

```
==> pg_stat_activity row
  smoke-test - 127.0.0.1|127.0.0.1
  OK application_name carries the client address: smoke-test - 127.0.0.1
  NOTE client_addr is 127.0.0.1. On a single host both sides are loopback, so
       this does not show the gap. It shows the mechanism.
```

That note matters for the demo: on one machine everything is loopback, so the
injected address and `client_addr` are the same and the screen proves nothing to
an audience. Section 5 covers making the gap visible.

### If it fails

**`PostgreSQL is not running`**
`sudo service postgresql start`. WSL does not start services on boot.

**`psql: error: connection to server ... FATAL: password authentication failed`**
Ubuntu's `pg_hba.conf` uses `scram-sha-256` for TCP connections, which the
script's role is set up for. If the cluster was initialised with `md5` or the
role predates the script, drop it and rerun:
`sudo -u postgres psql -c 'DROP ROLE prism_smoke'`.

**`application_name is 'smoke-test', expected 'smoke-test - <client address>'`**
The PROXY header was not applied. Everything here is loopback, so the default
`TRUSTED_PROXIES` should cover it. Compare the `Accepting PROXY headers only
from` line the script prints with the address HAProxy connects from.

**`Address already in use`**
Something else holds 6433 or 6434. Override with
`PRISM_PORT=7433 HAPROXY_PORT=7434 ./scripts/smoke-native.sh`.

---

## 3. PostgreSQL client tools and pgbench

`psql` arrives with `postgresql-client` above. `pgbench` is in
`postgresql-contrib`:

```bash
sudo apt-get install -y postgresql-contrib
pgbench --version
```

Match the client major version to the server you benchmark against. The
benchmark slide has to state both, so keep them aligned and known.

---

## 4. Making the client-address gap visible

### Do not demo as the `postgres` user

`guardian.yaml` ships with an `Admin_Full_Access` rule that gives loopback plus
the `postgres` user the `ALLOW` action, which **bypasses query inspection
entirely**. On the native path everything is loopback, so connecting as
`postgres` matches that rule and the Guardian part of the demo silently does
nothing: the blocked statement simply succeeds, and it looks like the feature is
broken rather than deliberately bypassed.

Use a separate unprivileged role for every demo connection:

```bash
sudo -u postgres psql -c "CREATE ROLE demo_app LOGIN PASSWORD 'demo';"
sudo -u postgres psql -c "CREATE DATABASE demo OWNER demo_app;"
```

`scripts/smoke-native.sh` already creates its own `prism_smoke` role for the
same reason. If you edit either the script or the demo to use `postgres`, the
Guardian beat stops proving anything.

To see the ALLOW path working *on purpose*, connect as `postgres` and show the
same blocked statement succeeding. That is a better demo than hiding the rule:
it shows the rule engine making a decision rather than doing nothing.

### Making the client-address gap visible

On a single host every address is `127.0.0.1`, so a screenshot of
`pg_stat_activity` shows the same value in `client_addr` and in the injected
suffix, and demonstrates nothing. Three ways to create a real gap, cheapest
first:

1. **Bind HAProxy to the WSL interface** rather than loopback. WSL2 gets its own
   address on a virtual switch (`ip addr show eth0`). Connect from Windows using
   that address: HAProxy then sees the Windows host address, injects it, and
   PostgreSQL still reports the WSL loopback in `client_addr`.
2. **A second machine on the same network**, if the venue or hotel network
   allows it. Most reliable visually, least reliable operationally. Do not
   depend on conference wifi.
3. **A pre-recorded capture** from a two-host setup, shown alongside the live
   single-host run. Honest if you say what it is.

Option 1 needs no network and no second machine, so it is the one to rehearse.

---

## 5. Preparing the machine for the conference

Do this at least a week before, not the night before.

```bash
# Build the release binary now so the demo never compiles on stage
cargo build --release --locked --manifest-path core/rust/Cargo.toml

# Prove the whole thing works with networking off.
#   Windows: aeroplane mode, or disable Wi-Fi and unplug Ethernet.
./scripts/smoke-native.sh
```

The native path has no images to pull and nothing to fetch at run time once the
apt packages and the release binary exist, which is the main reason it is the
demo path. The only network dependency is `cargo build`, and that is why you
build in advance.

Rehearse the full demo from a cold boot, including `sudo service postgresql
start`, at least five times, and once at the projector's resolution.

---

## 6. Container path (for other people)

Not needed for the demo. Kept because it is the setup most readers will try and
the one `docker-compose.yml` describes.

### Disk budget

| Item | Size |
| :--- | :--- |
| Docker Desktop | ~2.5 GB |
| WSL2 kernel + Ubuntu | ~1.5 GB |
| `postgres:15-alpine` + `haproxy:2.8-alpine` | ~450 MB |
| The `pg-prism` image | ~120 MB |
| `ext4.vhdx` growth during use | 2–5 GB |

**Budget 8 GB free.** The virtual disk grows and does not shrink by itself.

### Install and run

Install Docker Desktop and select **Use WSL 2 instead of Hyper-V**. Then
Settings → Resources → WSL Integration → enable it for Ubuntu. Verify:

```bash
docker version && docker compose version
cd ~/pg-prism && ./scripts/smoke.sh
```

### Differences from the native path

HAProxy runs in its own container, so it is **not** on loopback and the default
`TRUSTED_PROXIES` would refuse it. `docker-compose.yml` pins the bridge subnet
and names it in `TRUSTED_PROXIES` for exactly this reason. If you change the
network, change both.

```bash
docker network inspect pg-prism_pg-network | grep Subnet
```

### Reclaiming disk

```bash
docker system prune -a --volumes    # removes unused images too
```

```powershell
wsl --shutdown
Optimize-VHD -Path $env:LOCALAPPDATA\Docker\wsl\data\ext4.vhdx -Mode Full
```

Prune **before** pre-pulling for a demo, never after: pruning afterwards removes
the images you just staged.

---

## 7. Known environment issues

- **`native-tls` uses a different backend per platform**: SChannel on Windows,
  OpenSSL on Linux, Security.framework on macOS. TLS behaviour verified on one
  is not verified on the others. CI runs Linux, which is what deployments use,
  and the demo runs Linux inside WSL.
- **The proxy shells out to the `openssl` CLI** to mint its self-signed
  certificate on first start. Present in the Docker image, on CI, and in
  Ubuntu. Not present on a bare Windows host, so `SSL_ENABLED=true` there logs
  a failure and falls back to plaintext. `smoke-native.sh` sets
  `SSL_ENABLED=false` deliberately; TLS has its own coverage in CI.
- **The generated `server.crt` / `server.key` / `identity.p12` land in the
  working directory.** They are gitignored. Delete them to force regeneration.
- **WSL does not start services on boot.** `sudo service postgresql start` is
  part of the demo runbook, not a one-off.

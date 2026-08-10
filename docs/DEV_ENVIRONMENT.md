# Development environment

The Rust core builds and its fast test suite runs anywhere Rust does, including
Windows with no other tooling. Three things need Linux containers:

| Deliverable | Needs |
| :--- | :--- |
| `scripts/smoke.sh` | Docker + compose |
| The conference demo | Docker + compose, working **offline** |
| The benchmark (`bench/`) | Docker + compose, `pgbench`, `psql` |

CI covers the real-PostgreSQL tests on Linux, so you do not need Docker to
develop or to have the protocol tests run. You need it for the three above.

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

## 2. WSL2 and Docker Desktop on Windows

### Disk space, read this first

Docker Desktop with the WSL2 backend needs roughly:

| Item | Size |
| :--- | :--- |
| Docker Desktop installation | ~2.5 GB |
| WSL2 kernel + Ubuntu distribution | ~1.5 GB |
| `postgres:16` + `haproxy:2.8-alpine` images | ~450 MB |
| The `pg-prism` image you build | ~120 MB |
| `ext4.vhdx` growth during use | 2–5 GB |

**Budget 8 GB free.** The virtual disk grows and does not shrink on its own;
section 5 covers reclaiming it.

If that is not available, use a Linux machine or a VM for the demo and the
benchmark. Do not run the conference demo on a laptop that is near full.

### Install

Run in an **Administrator** PowerShell:

```powershell
wsl --install -d Ubuntu
```

This enables the Virtual Machine Platform and WSL features, installs the WSL2
kernel and Ubuntu, and sets WSL2 as the default. It requires a reboot. On some
systems virtualisation must be enabled in the firmware first (Intel VT-x or
AMD-V); if `wsl --install` reports that, change it in the BIOS/UEFI and retry.

After rebooting, Ubuntu opens and asks for a username and password. Then:

```powershell
wsl --set-default-version 2
wsl -l -v          # Ubuntu should show VERSION 2
```

Install Docker Desktop from https://www.docker.com/products/docker-desktop/ and,
during setup, select **Use WSL 2 instead of Hyper-V**. Once it is running:

Settings → Resources → WSL Integration → enable it for **Ubuntu**.

Verify from a plain (non-admin) shell:

```bash
docker version
docker compose version
docker run --rm hello-world
```

### Which shell to run things from

Run `scripts/smoke.sh`, the demo and the benchmark **from inside WSL**, not from
Git Bash. Two reasons: the scripts assume GNU coreutils, and files under
`/mnt/c` are far slower than files in the WSL filesystem, which matters for the
benchmark.

Clone the repository inside WSL rather than working across the mount:

```bash
# inside WSL
git clone https://github.com/heyobi/pg-prism.git ~/pg-prism
cd ~/pg-prism
```

---

## 3. PostgreSQL client tools and pgbench

`psql` and `pgbench` are needed on the **host** for the benchmark. The smoke
test does not need them: it runs `psql` inside the postgres container.

Inside WSL:

```bash
sudo apt-get update
sudo apt-get install -y postgresql-client-16
psql --version
pgbench --version
```

If `postgresql-client-16` is not in your distribution's archive, add the PGDG
repository:

```bash
sudo apt-get install -y curl ca-certificates
sudo install -d /usr/share/postgresql-common/pgdg
sudo curl -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
  --fail https://www.postgresql.org/media/keys/ACCC4CF8.asc
echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] \
https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
  | sudo tee /etc/apt/sources.list.d/pgdg.list
sudo apt-get update
sudo apt-get install -y postgresql-client-16
```

Match the client major version to the server you benchmark against. `pgbench`
from a newer client against an older server generally works, but the benchmark
slide has to state both versions, so keep them aligned and known.

---

## 4. Verifying the stack

```bash
cd ~/pg-prism
./scripts/smoke.sh
```

It builds the image, starts PostgreSQL, PG-Prism and HAProxy, sends one
connection along the full path, prints the `pg_stat_activity` row, and tears
down. `KEEP=1 ./scripts/smoke.sh` leaves the stack running.

A pass looks like:

```
==> pg_stat_activity row
  smoke-test - 172.29.0.4|172.29.0.3
  OK application_name carries the real client address: smoke-test - 172.29.0.4
```

### If it fails

**`application_name is 'smoke-test', expected 'smoke-test - <client address>'`**
The PROXY header was not applied. Almost always the trusted-proxy allowlist:
HAProxy is a separate container, so it is not on loopback, and
`docker-compose.yml` has to name the compose subnet in `TRUSTED_PROXIES`.
Compare the `Accepting PROXY headers only from` line in the proxy log against
the actual network:

```bash
docker network inspect pg-prism_pg-network | grep Subnet
```

**`Refused connection from <addr>: not in TRUSTED_PROXIES`**
Same cause, stated directly by the proxy. Set `TRUSTED_PROXIES` to the subnet
shown above.

**PostgreSQL never becomes ready**
Usually a port clash on 5432 with a PostgreSQL already installed on the host.
Either stop it or remove the `ports:` mapping for the `postgres` service; the
stack does not need it published.

---

## 5. Preparing the machine for the conference

Do this at least a week before, not the night before.

```bash
# Pre-pull everything so the demo needs no network
docker compose pull
docker compose build

# Prove it works with networking off
#   Windows: disable Wi-Fi and unplug Ethernet, or use aeroplane mode
./scripts/smoke.sh
```

Then reclaim disk space, because the WSL virtual disk does not shrink by
itself:

```bash
docker system prune -a --volumes    # careful: removes unused images too
```

```powershell
# From Windows, after shutting WSL down
wsl --shutdown
Optimize-VHD -Path $env:LOCALAPPDATA\Docker\wsl\data\ext4.vhdx -Mode Full
```

`Optimize-VHD` needs the Hyper-V module. If it is unavailable, `diskpart` with
`compact vdisk` does the same job.

**Do not** run `docker system prune` after pre-pulling for the demo; it will
remove the images you just staged and the demo will need the network again.
Prune first, stage second.

---

## 6. Known environment issues

- **`native-tls` uses a different backend per platform**: SChannel on Windows,
  OpenSSL on Linux, Security.framework on macOS. TLS behaviour verified on one
  is not verified on the others. CI runs Linux, which is what deployments use.
- **The proxy shells out to the `openssl` CLI** to mint its self-signed
  certificate on first start. Present in the Docker image and on CI. Not present
  on a bare Windows host, so `SSL_ENABLED=true` there will log a failure and
  fall back to plaintext.
- **The generated `server.crt` / `server.key` / `identity.p12` land in the
  working directory.** They are gitignored. Delete them to force regeneration.

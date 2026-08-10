#!/usr/bin/env python3
"""
PG-Prism benchmark harness.

Measures the latency cost of putting a proxy in the path, across five
configurations and two workloads.

This harness reports numbers. It does not interpret them, it does not draw
conclusions, and it contains no branch that treats a favourable result
differently from an unfavourable one. The only thing it asserts is that the
measurements are not impossible: a proxy cannot be faster than the thing it
forwards to, so if one measures faster by more than the noise floor, the run has
gone wrong and the harness fails rather than reporting it.

Requires: python3 (stdlib only), pgbench, psql, haproxy, and optionally
pgbouncer. Run `--check` first to see what is missing.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import platform
import random
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# --------------------------------------------------------------------------
# Ports. Deliberately not the defaults, so a benchmark run cannot collide with
# a development stack that happens to be up.
# --------------------------------------------------------------------------
PORT_HAPROXY = 7434
PORT_PRISM_PLAIN = 7433
PORT_PRISM_TLS = 7435
PORT_PGBOUNCER = 7432

REPO_ROOT = Path(__file__).resolve().parent.parent
PRISM_BIN = REPO_ROOT / "core" / "rust" / "target" / "release" / "pg-prism-rust"


# --------------------------------------------------------------------------
# Configurations under test
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Config:
    name: str
    port: int
    sslmode: str
    # The configuration this one sits behind. A proxy cannot be faster than
    # what it forwards to; that is the only sanity assertion in this harness.
    behind: str | None
    description: str


CONFIGS: list[Config] = [
    Config("direct", 5432, "disable", None,
           "client -> PostgreSQL"),
    Config("haproxy", PORT_HAPROXY, "disable", "direct",
           "client -> HAProxy -> PostgreSQL"),
    Config("prism_plain", PORT_HAPROXY, "disable", "haproxy",
           "client -> HAProxy -> PG-Prism (plaintext) -> PostgreSQL"),
    Config("prism_tls", PORT_HAPROXY, "require", "haproxy",
           "client -> HAProxy -> PG-Prism (TLS termination) -> PostgreSQL"),
    Config("pgbouncer", PORT_HAPROXY, "disable", "haproxy",
           "client -> HAProxy -> PgBouncer -> PostgreSQL"),
]

BY_NAME = {c.name: c for c in CONFIGS}

# prism_tls does strictly more work than prism_plain, so it must not measure
# faster either. Kept separate from `behind` because it is not a topology
# relationship.
EXTRA_ORDERING = [("prism_tls", "prism_plain")]

WORKLOADS = {
    # Read-only, one persistent connection per client. Isolates per-statement
    # forwarding cost.
    "select": ["-S"],
    # Reconnect for every transaction. This is where handshake cost lives:
    # PROXY header, startup parse, injection, and for prism_tls a full TLS
    # handshake, all paid per transaction.
    "connect": ["-S", "-C"],
}


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def which(name: str) -> str | None:
    return shutil.which(name)


def wait_for_port(port: int, host: str = "127.0.0.1", timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.2)
    return False


def percentile(values: list[float], q: float) -> float:
    """Nearest-rank percentile: the smallest value at or below which at least
    q% of samples fall. No interpolation, so a reported p99 is a latency that
    actually occurred.

    rank = ceil(q/100 * n), 1-based. Written out rather than using round(),
    which bankers-rounds 99.5 to 100 and quietly turned p99 into p100.
    """
    if not values:
        return float("nan")
    ordered = sorted(values)
    n = len(ordered)
    rank = math.ceil(q / 100.0 * n)
    rank = max(1, min(n, rank))
    return ordered[rank - 1]


# --------------------------------------------------------------------------
# Environment capture
# --------------------------------------------------------------------------
def capture_environment(pg: "PgTarget") -> dict:
    env: dict = {
        "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": platform.python_version(),
    }

    def cmd_version(binary: str, args: list[str]) -> str | None:
        if not which(binary):
            return None
        r = run([binary] + args)
        return (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr) else None

    env["versions"] = {
        "pgbench": cmd_version("pgbench", ["--version"]),
        "psql": cmd_version("psql", ["--version"]),
        "haproxy": cmd_version("haproxy", ["-v"]),
        "pgbouncer": cmd_version("pgbouncer", ["--version"]),
        "cargo": cmd_version("cargo", ["--version"]),
        "openssl": cmd_version("openssl", ["version"]),
    }

    # CPU
    try:
        cpuinfo = Path("/proc/cpuinfo").read_text()
        model = re.search(r"model name\s*:\s*(.+)", cpuinfo)
        env["cpu_model"] = model.group(1).strip() if model else None
        env["cpu_logical"] = cpuinfo.count("processor\t:")
    except OSError:
        env["cpu_model"] = None
        env["cpu_logical"] = os.cpu_count()

    # Memory
    try:
        meminfo = Path("/proc/meminfo").read_text()
        total = re.search(r"MemTotal:\s*(\d+) kB", meminfo)
        env["mem_total_mb"] = int(total.group(1)) // 1024 if total else None
    except OSError:
        env["mem_total_mb"] = None

    # Frequency scaling. Not fatal, but it moves numbers between runs, so it
    # must appear next to them.
    gov = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    env["cpu_governor"] = gov.read_text().strip() if gov.exists() else None
    boost = Path("/sys/devices/system/cpu/cpufreq/boost")
    env["cpu_boost"] = boost.read_text().strip() if boost.exists() else None

    # Virtualisation. WSL2 in particular has a scheduler and a clock that are
    # not a bare-metal server's, and anyone reading these numbers must know.
    env["virtualisation"] = None
    if which("systemd-detect-virt"):
        env["virtualisation"] = run(["systemd-detect-virt"]).stdout.strip() or None
    try:
        if "microsoft" in Path("/proc/version").read_text().lower():
            env["virtualisation"] = (env["virtualisation"] or "") + " (WSL)"
    except OSError:
        pass

    # Load average at capture time.
    try:
        env["loadavg"] = os.getloadavg()
    except (OSError, AttributeError):
        env["loadavg"] = None

    # PostgreSQL settings that change throughput by more than a proxy does.
    settings = {}
    for name in ("server_version", "shared_buffers", "work_mem", "max_connections",
                 "fsync", "synchronous_commit", "full_page_writes",
                 "wal_level", "max_wal_size", "checkpoint_timeout",
                 "ssl", "password_encryption", "track_activities"):
        out = pg.psql_value(f"SHOW {name}")
        if out is not None:
            settings[name] = out
    env["postgres_settings"] = settings

    return env


# --------------------------------------------------------------------------
# PostgreSQL target
# --------------------------------------------------------------------------
@dataclass
class PgTarget:
    host: str
    port: int
    user: str
    password: str
    dbname: str

    def env(self, port: int | None = None, sslmode: str = "disable") -> dict:
        e = dict(os.environ)
        e.update({
            "PGHOST": self.host,
            "PGPORT": str(port if port is not None else self.port),
            "PGUSER": self.user,
            "PGPASSWORD": self.password,
            "PGDATABASE": self.dbname,
            "PGSSLMODE": sslmode,
            # Fixed so it cannot vary between configurations. PG-Prism will
            # append the client address to it; that is the work being measured.
            "PGAPPNAME": "pgbench-harness",
        })
        return e

    def psql_value(self, sql: str) -> str | None:
        r = run(["psql", "-tAc", sql], env=self.env())
        if r.returncode != 0:
            return None
        return r.stdout.strip() or None


# --------------------------------------------------------------------------
# Service management
# --------------------------------------------------------------------------
class Services:
    """Starts and stops the proxies. Every process this class starts is
    recorded and killed on teardown, including on an exception."""

    def __init__(self, pg: PgTarget, workdir: Path):
        self.pg = pg
        self.workdir = workdir
        self.procs: list[tuple[str, subprocess.Popen]] = []
        self.workdir.mkdir(parents=True, exist_ok=True)

    # -- HAProxy ---------------------------------------------------------
    def start_haproxy(self, backend_port: int, send_proxy: bool) -> None:
        cfg = self.workdir / "haproxy.cfg"
        cfg.write_text(f"""\
global
    log stdout format raw local0
    maxconn 4096
defaults
    log     global
    mode    tcp
    timeout connect 10s
    timeout client  10m
    timeout server  10m
frontend bench_in
    bind 127.0.0.1:{PORT_HAPROXY}
    default_backend bench_out
backend bench_out
    server target 127.0.0.1:{backend_port}{' send-proxy' if send_proxy else ''}
""")
        p = subprocess.Popen(
            ["haproxy", "-f", str(cfg), "-db"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.procs.append(("haproxy", p))
        if not wait_for_port(PORT_HAPROXY):
            raise RuntimeError("HAProxy did not start listening")

    # -- PG-Prism --------------------------------------------------------
    def start_prism(self, listen_port: int, ssl: bool) -> None:
        if not PRISM_BIN.exists():
            raise RuntimeError(
                f"{PRISM_BIN} not found. Build it first:\n"
                f"  cargo build --release --locked --manifest-path core/rust/Cargo.toml"
            )
        rundir = self.workdir / f"prism-{listen_port}"
        rundir.mkdir(exist_ok=True)
        # No guardian.yaml is written here on purpose. Guardian rule evaluation
        # is a separate cost from address injection, and mixing them would make
        # the number impossible to attribute.
        env = dict(os.environ)
        env.update({
            "LISTEN_HOST": "127.0.0.1",
            "LISTEN_PORT": str(listen_port),
            "PG_HOST": self.pg.host,
            "PG_PORT": str(self.pg.port),
            "SSL_ENABLED": "true" if ssl else "false",
            "RUST_LOG": "warn",  # info logs one line per connection, which the
                                 # -C workload would turn into a benchmark of
                                 # the logger.
        })
        p = subprocess.Popen(
            [str(PRISM_BIN)], cwd=rundir, env=env,
            stdout=(rundir / "prism.log").open("w"), stderr=subprocess.STDOUT,
        )
        self.procs.append((f"pg-prism:{listen_port}", p))
        if not wait_for_port(listen_port, timeout=30.0):
            raise RuntimeError(
                f"PG-Prism did not start listening on {listen_port}; "
                f"see {rundir / 'prism.log'}"
            )

    # -- PgBouncer -------------------------------------------------------
    def start_pgbouncer(self) -> None:
        if not which("pgbouncer"):
            raise RuntimeError("pgbouncer is not installed")
        d = self.workdir / "pgbouncer"
        d.mkdir(exist_ok=True)
        (d / "users.txt").write_text(f'"{self.pg.user}" "{self.pg.password}"\n')
        (d / "users.txt").chmod(0o600)
        (d / "pgbouncer.ini").write_text(f"""\
[databases]
{self.pg.dbname} = host={self.pg.host} port={self.pg.port} dbname={self.pg.dbname}

[pgbouncer]
listen_addr = 127.0.0.1
listen_port = {PORT_PGBOUNCER}
auth_type = trust
auth_file = {d / 'users.txt'}
pool_mode = session
max_client_conn = 1000
default_pool_size = 100
logfile = {d / 'pgbouncer.log'}
pidfile = {d / 'pgbouncer.pid'}
unix_socket_dir = {d}

; The feature this configuration exists to compare against.
application_name_add_host = 1
""")
        p = subprocess.Popen(
            ["pgbouncer", str(d / "pgbouncer.ini")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.procs.append(("pgbouncer", p))
        if not wait_for_port(PORT_PGBOUNCER):
            raise RuntimeError("PgBouncer did not start listening")

    # -- lifecycle -------------------------------------------------------
    def bring_up(self, cfg: Config) -> None:
        if cfg.name == "direct":
            return
        if cfg.name == "haproxy":
            self.start_haproxy(self.pg.port, send_proxy=False)
        elif cfg.name == "prism_plain":
            self.start_prism(PORT_PRISM_PLAIN, ssl=False)
            self.start_haproxy(PORT_PRISM_PLAIN, send_proxy=True)
        elif cfg.name == "prism_tls":
            self.start_prism(PORT_PRISM_TLS, ssl=True)
            self.start_haproxy(PORT_PRISM_TLS, send_proxy=True)
        elif cfg.name == "pgbouncer":
            self.start_pgbouncer()
            # No send-proxy: PgBouncer cannot read a PROXY header and hangs if
            # sent one. See AUDIT.md section 15.2.
            self.start_haproxy(PORT_PGBOUNCER, send_proxy=False)
        else:
            raise ValueError(f"unknown configuration {cfg.name}")

    def tear_down(self) -> None:
        for name, p in reversed(self.procs):
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=5)
        self.procs.clear()
        time.sleep(1)


# --------------------------------------------------------------------------
# Measurement
# --------------------------------------------------------------------------
@dataclass
class Measurement:
    config: str
    workload: str
    repetition: int
    clients: int
    duration_s: int
    tps: float
    latencies_us: list[float] = field(repr=False, default_factory=list)

    def stats(self) -> dict:
        v = self.latencies_us
        return {
            "samples": len(v),
            "tps": self.tps,
            "p50_ms": percentile(v, 50) / 1000.0 if v else float("nan"),
            "p95_ms": percentile(v, 95) / 1000.0 if v else float("nan"),
            "p99_ms": percentile(v, 99) / 1000.0 if v else float("nan"),
            "mean_ms": statistics.fmean(v) / 1000.0 if v else float("nan"),
            "max_ms": max(v) / 1000.0 if v else float("nan"),
        }


def parse_pgbench_logs(logdir: Path, prefix: str) -> list[float]:
    """pgbench --log writes one line per transaction:
       client_id transaction_no time script_no time_epoch time_us [...]
    where `time` (field index 2) is the latency in microseconds."""
    latencies: list[float] = []
    for f in sorted(logdir.glob(f"{prefix}.*")):
        with f.open() as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3:
                    continue
                try:
                    latencies.append(float(parts[2]))
                except ValueError:
                    continue
    return latencies


def run_pgbench(pg: PgTarget, cfg: Config, workload: str, *, clients: int,
                jobs: int, duration: int, logdir: Path, prefix: str,
                collect: bool) -> tuple[float, list[float]]:
    logdir.mkdir(parents=True, exist_ok=True)
    for stale in logdir.glob(f"{prefix}.*"):
        stale.unlink()

    cmd = [
        "pgbench",
        "-n",                       # never vacuum: it would run for one config
                                    # and not the next
        *WORKLOADS[workload],
        "-c", str(clients),
        "-j", str(jobs),
        "-T", str(duration),
        "-P", "30",
    ]
    if collect:
        cmd += ["--log", f"--log-prefix={logdir / prefix}"]
    cmd += ["-h", "127.0.0.1", "-p", str(cfg.port), pg.dbname]

    r = run(cmd, env=pg.env(port=cfg.port, sslmode=cfg.sslmode))
    if r.returncode != 0:
        raise RuntimeError(
            f"pgbench failed for {cfg.name}/{workload}:\n{r.stdout}\n{r.stderr}"
        )

    m = re.search(r"^tps = ([\d.]+)", r.stdout, re.MULTILINE)
    tps = float(m.group(1)) if m else float("nan")
    lat = parse_pgbench_logs(logdir, prefix) if collect else []
    return tps, lat


def measure(pg: PgTarget, services: Services, cfg: Config, workload: str,
            rep: int, args) -> Measurement:
    services.bring_up(cfg)
    try:
        logdir = Path(args.outdir) / "raw" / f"{cfg.name}_{workload}_r{rep}"

        log(f"    warmup {args.warmup}s")
        run_pgbench(pg, cfg, workload, clients=args.clients, jobs=args.jobs,
                    duration=args.warmup, logdir=logdir, prefix="warmup",
                    collect=False)

        log(f"    measure {args.duration}s")
        tps, lat = run_pgbench(pg, cfg, workload, clients=args.clients,
                               jobs=args.jobs, duration=args.duration,
                               logdir=logdir, prefix="run", collect=True)
    finally:
        services.tear_down()

    return Measurement(cfg.name, workload, rep, args.clients, args.duration, tps, lat)


# --------------------------------------------------------------------------
# Noise floor
# --------------------------------------------------------------------------
def measure_noise_floor(pg: PgTarget, services: Services, args) -> dict:
    """Run the baseline against itself, repeatedly, changing nothing.

    Every difference this produces is measurement noise. Any difference between
    two real configurations that is smaller than this number means nothing, and
    printing it first is what stops a reader treating a 2% gap as a result.
    """
    log("Noise floor: repeating the baseline configuration with nothing changed")
    direct = BY_NAME["direct"]
    out: dict = {}
    for workload in args.workloads:
        runs = []
        for i in range(args.noise_reps):
            log(f"  {workload} noise run {i + 1}/{args.noise_reps}")
            m = measure(pg, services, direct, workload, 900 + i, args)
            runs.append(m)
        p50s = [r.stats()["p50_ms"] for r in runs]
        p99s = [r.stats()["p99_ms"] for r in runs]
        tpss = [r.tps for r in runs]
        out[workload] = {
            "runs": args.noise_reps,
            "p50_ms": p50s,
            "p99_ms": p99s,
            "tps": tpss,
            "p50_spread_ms": max(p50s) - min(p50s),
            "p50_spread_pct": (max(p50s) - min(p50s)) / statistics.fmean(p50s) * 100.0,
            "p99_spread_ms": max(p99s) - min(p99s),
            "tps_spread_pct": (max(tpss) - min(tpss)) / statistics.fmean(tpss) * 100.0,
        }
    return out


def print_noise_floor(noise: dict) -> None:
    print()
    print("=" * 72)
    print("NOISE FLOOR — the same configuration measured against itself")
    print("=" * 72)
    print("Differences smaller than these are not results.")
    print()
    for workload, n in noise.items():
        print(f"  {workload}:")
        print(f"    p50 spread : {n['p50_spread_ms']:.3f} ms  ({n['p50_spread_pct']:.1f}%)")
        print(f"    p99 spread : {n['p99_spread_ms']:.3f} ms")
        print(f"    tps spread : {n['tps_spread_pct']:.1f}%")
        print(f"    p50 values : {', '.join(f'{v:.3f}' for v in n['p50_ms'])}")
    print("=" * 72)
    print()


# --------------------------------------------------------------------------
# Sanity assertions
# --------------------------------------------------------------------------
def check_sanity(results: dict[tuple[str, str], list[Measurement]],
                 noise: dict) -> list[str]:
    """A proxy cannot be faster than what it forwards to.

    If one measures faster by more than the noise floor can explain, the
    measurement is wrong — a service did not start, traffic bypassed a hop, a
    warmup leaked into a run. Report it as a failure. Do not publish it as a
    finding, and do not explain it away.
    """
    failures: list[str] = []

    pairs = [(c.name, c.behind) for c in CONFIGS if c.behind] + EXTRA_ORDERING

    for workload in {w for (_, w) in results}:
        margin = noise.get(workload, {}).get("p50_spread_ms", 0.0)
        for faster_name, slower_name in pairs:
            a = results.get((faster_name, workload))
            b = results.get((slower_name, workload))
            if not a or not b:
                continue
            a_p50 = statistics.median([m.stats()["p50_ms"] for m in a])
            b_p50 = statistics.median([m.stats()["p50_ms"] for m in b])
            if b_p50 - a_p50 > margin:
                failures.append(
                    f"{workload}: {faster_name} p50 {a_p50:.3f} ms is faster than "
                    f"{slower_name} p50 {b_p50:.3f} ms, which it sits behind, by "
                    f"{b_p50 - a_p50:.3f} ms — more than the {margin:.3f} ms noise "
                    f"floor. A proxy cannot be faster than what it forwards to; "
                    f"this measurement is wrong."
                )
    return failures


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
def write_csv(path: Path, measurements: list[Measurement]) -> None:
    with path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["config", "workload", "repetition", "clients", "duration_s",
                    "samples", "tps", "p50_ms", "p95_ms", "p99_ms", "mean_ms", "max_ms"])
        for m in measurements:
            s = m.stats()
            w.writerow([m.config, m.workload, m.repetition, m.clients, m.duration_s,
                        s["samples"], f"{m.tps:.2f}", f"{s['p50_ms']:.4f}",
                        f"{s['p95_ms']:.4f}", f"{s['p99_ms']:.4f}",
                        f"{s['mean_ms']:.4f}", f"{s['max_ms']:.4f}"])


def write_raw_latencies(outdir: Path, measurements: list[Measurement]) -> None:
    d = outdir / "latencies"
    d.mkdir(parents=True, exist_ok=True)
    for m in measurements:
        f = d / f"{m.config}_{m.workload}_r{m.repetition}.txt"
        f.write_text("\n".join(f"{v:.1f}" for v in m.latencies_us))


def render_markdown(env: dict, noise: dict, measurements: list[Measurement],
                    args, failures: list[str]) -> str:
    by: dict[tuple[str, str], list[Measurement]] = {}
    for m in measurements:
        by.setdefault((m.config, m.workload), []).append(m)

    lines: list[str] = []
    lines.append("# PG-Prism benchmark results")
    lines.append("")
    lines.append("Generated by `bench/harness.py`. The harness reports numbers and does")
    lines.append("not interpret them; any conclusion below this line was added by hand.")
    lines.append("")

    lines.append("## Method")
    lines.append("")
    lines.append(f"- Workloads: {', '.join(args.workloads)} "
                 f"(`pgbench -S` and `pgbench -S -C`)")
    lines.append(f"- Clients: {args.clients}, threads: {args.jobs}, scale: {args.scale}")
    lines.append(f"- Warmup: {args.warmup}s discarded, measured: {args.duration}s")
    lines.append(f"- Repetitions: {args.reps}, configurations randomised within each")
    lines.append(f"- Percentiles: nearest-rank from `pgbench --log`, per transaction")
    lines.append("")

    lines.append("## Environment")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(env, indent=2, sort_keys=True))
    lines.append("```")
    lines.append("")

    lines.append("## Noise floor")
    lines.append("")
    lines.append("The baseline configuration measured against itself, changing nothing.")
    lines.append("**Differences smaller than these are not results.**")
    lines.append("")
    lines.append("| Workload | p50 spread (ms) | p50 spread (%) | p99 spread (ms) | tps spread (%) |")
    lines.append("|---|---|---|---|---|")
    for w, n in noise.items():
        lines.append(f"| {w} | {n['p50_spread_ms']:.3f} | {n['p50_spread_pct']:.1f} "
                     f"| {n['p99_spread_ms']:.3f} | {n['tps_spread_pct']:.1f} |")
    lines.append("")

    lines.append("## Results")
    lines.append("")
    for workload in args.workloads:
        lines.append(f"### `{workload}`")
        lines.append("")
        lines.append("| Configuration | Path | tps | p50 (ms) | p95 (ms) | p99 (ms) |")
        lines.append("|---|---|---|---|---|---|")
        for c in CONFIGS:
            ms = by.get((c.name, workload))
            if not ms:
                lines.append(f"| `{c.name}` | {c.description} | — | — | — | — |")
                continue
            med = lambda k: statistics.median([m.stats()[k] for m in ms])  # noqa: E731
            tps = statistics.median([m.tps for m in ms])
            lines.append(f"| `{c.name}` | {c.description} | {tps:.0f} "
                         f"| {med('p50_ms'):.3f} | {med('p95_ms'):.3f} "
                         f"| {med('p99_ms'):.3f} |")
        lines.append("")
        lines.append(f"Median across {args.reps} repetitions. Per-repetition values are in "
                     f"`raw/results.csv`.")
        lines.append("")

    lines.append("## Sanity checks")
    lines.append("")
    if failures:
        lines.append("**FAILED.** These measurements are impossible and must not be used:")
        lines.append("")
        for f in failures:
            lines.append(f"- {f}")
    else:
        lines.append("Passed. No configuration measured faster than the configuration it")
        lines.append("sits behind by more than the noise floor.")
    lines.append("")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def check_prerequisites(args) -> list[str]:
    missing = []
    for b in ("pgbench", "psql", "haproxy"):
        if not which(b):
            missing.append(f"{b} is not on PATH")
    if "pgbouncer" in args.configs and not which("pgbouncer"):
        missing.append("pgbouncer is not on PATH (or drop it with --configs)")
    if not PRISM_BIN.exists() and any(c.startswith("prism") for c in args.configs):
        missing.append(f"{PRISM_BIN} does not exist; build with "
                       f"`cargo build --release --locked "
                       f"--manifest-path core/rust/Cargo.toml`")
    return missing


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--outdir", default="bench/results",
                   help="where to write results (default: bench/results)")
    p.add_argument("--duration", type=int, default=120,
                   help="measured seconds per run (default: 120, minimum 120)")
    p.add_argument("--warmup", type=int, default=30,
                   help="discarded seconds before each run (default: 30, minimum 30)")
    p.add_argument("--reps", type=int, default=3,
                   help="repetitions of the full set (default: 3)")
    p.add_argument("--noise-reps", type=int, default=3,
                   help="baseline-against-itself runs (default: 3)")
    p.add_argument("--clients", type=int, default=8)
    p.add_argument("--jobs", type=int, default=4)
    p.add_argument("--scale", type=int, default=10)
    p.add_argument("--workloads", nargs="+", default=list(WORKLOADS),
                   choices=list(WORKLOADS))
    p.add_argument("--configs", nargs="+", default=[c.name for c in CONFIGS],
                   choices=[c.name for c in CONFIGS])
    p.add_argument("--seed", type=int, default=None,
                   help="seed for the configuration ordering (default: random, recorded)")
    p.add_argument("--skip-init", action="store_true",
                   help="do not run pgbench -i")
    p.add_argument("--check", action="store_true",
                   help="verify prerequisites and exit")
    p.add_argument("--allow-short", action="store_true",
                   help="permit durations below the documented minimums. For "
                        "developing the harness only; results are not comparable.")
    args = p.parse_args()

    if not args.allow_short and (args.duration < 120 or args.warmup < 30):
        print("Refusing to run: the documented method is at least 30s warmup and\n"
              "120s measured. Short runs do not settle and are not comparable to\n"
              "anything. Pass --allow-short if you are developing the harness.",
              file=sys.stderr)
        return 2

    missing = check_prerequisites(args)
    if args.check:
        if missing:
            print("Missing:")
            for m in missing:
                print(f"  - {m}")
            return 1
        print("All prerequisites present.")
        return 0
    if missing:
        for m in missing:
            print(f"error: {m}", file=sys.stderr)
        return 1

    pg = PgTarget(
        host=os.environ.get("PGHOST", "127.0.0.1"),
        port=int(os.environ.get("PGPORT", "5432")),
        user=os.environ.get("PGUSER", "postgres"),
        password=os.environ.get("PGPASSWORD", ""),
        dbname=os.environ.get("PGDATABASE", "postgres"),
    )

    if pg.psql_value("SELECT 1") != "1":
        print(f"error: cannot reach PostgreSQL at {pg.host}:{pg.port} as {pg.user}",
              file=sys.stderr)
        return 1

    seed = args.seed if args.seed is not None else random.randrange(2**31)
    rng = random.Random(seed)
    log(f"Configuration ordering seed: {seed}")

    outdir = Path(args.outdir)
    (outdir / "raw").mkdir(parents=True, exist_ok=True)

    if not args.skip_init:
        log(f"Initialising pgbench tables at scale {args.scale}")
        r = run(["pgbench", "-i", "-q", "-s", str(args.scale), pg.dbname], env=pg.env())
        if r.returncode != 0:
            print(f"error: pgbench -i failed:\n{r.stderr}", file=sys.stderr)
            return 1

    log("Capturing environment")
    env = capture_environment(pg)
    if env.get("cpu_governor") not in (None, "performance"):
        log(f"  WARNING: cpu governor is {env['cpu_governor']}, not performance. "
            f"Recorded, not corrected.")
    if env.get("virtualisation"):
        log(f"  NOTE: running under {env['virtualisation']}. Recorded.")

    workdir = Path(tempfile.mkdtemp(prefix="pg-prism-bench-"))
    services = Services(pg, workdir)
    measurements: list[Measurement] = []

    def cleanup(*_):
        services.tear_down()

    signal.signal(signal.SIGINT, lambda *a: (cleanup(), sys.exit(130)))
    signal.signal(signal.SIGTERM, lambda *a: (cleanup(), sys.exit(143)))

    try:
        noise = measure_noise_floor(pg, services, args)
        print_noise_floor(noise)

        selected = [BY_NAME[n] for n in args.configs]
        total = args.reps * len(args.workloads) * len(selected)
        done = 0
        for rep in range(1, args.reps + 1):
            # Randomised within the repetition, so a machine that drifts over
            # the course of an hour does not systematically favour whichever
            # configuration happens to run first.
            order = selected[:]
            rng.shuffle(order)
            log(f"Repetition {rep}/{args.reps}, order: "
                f"{', '.join(c.name for c in order)}")
            for cfg in order:
                for workload in args.workloads:
                    done += 1
                    log(f"  [{done}/{total}] {cfg.name} / {workload}")
                    measurements.append(measure(pg, services, cfg, workload, rep, args))
    finally:
        services.tear_down()
        shutil.rmtree(workdir, ignore_errors=True)

    by: dict[tuple[str, str], list[Measurement]] = {}
    for m in measurements:
        by.setdefault((m.config, m.workload), []).append(m)

    failures = check_sanity(by, noise)

    env["ordering_seed"] = seed
    write_csv(outdir / "raw" / "results.csv", measurements)
    write_raw_latencies(outdir / "raw", measurements)
    (outdir / "raw" / "environment.json").write_text(json.dumps(env, indent=2, sort_keys=True))
    (outdir / "noise.json").write_text(json.dumps(noise, indent=2))
    (outdir / "BENCHMARK.md").write_text(
        render_markdown(env, noise, measurements, args, failures))

    log(f"Wrote {outdir / 'BENCHMARK.md'} and {outdir / 'raw' / 'results.csv'}")

    if failures:
        print()
        print("=" * 72)
        print("SANITY CHECK FAILED")
        print("=" * 72)
        for f in failures:
            print(f"  - {f}")
        print()
        print("These numbers must not be published. Find the measurement error.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

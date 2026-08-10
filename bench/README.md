# Benchmark harness

Measures what putting a proxy in the path costs, across five configurations and
two workloads.

The harness reports numbers. It does not interpret them, and it contains no
branch that treats a favourable result differently from an unfavourable one. The
only thing it asserts is that the measurements are not impossible.

## Requirements

`python3` (stdlib only), `pgbench`, `psql`, `haproxy`, and optionally
`pgbouncer`. A release build of the proxy:

```bash
cargo build --release --locked --manifest-path core/rust/Cargo.toml
python3 bench/harness.py --check
```

## Running it

```bash
export PGHOST=127.0.0.1 PGPORT=5432 PGUSER=... PGPASSWORD=... PGDATABASE=...
python3 bench/harness.py
```

A full run is **five configurations × two workloads × three repetitions × 150 s**,
plus the noise floor: roughly 80 minutes. Nothing else should be running on the
machine.

Output lands in `bench/results/` (git-ignored):

```
bench/results/
  BENCHMARK.md            rendered tables for review
  noise.json
  raw/
    results.csv           one row per run, all repetitions
    environment.json
    latencies/            every transaction latency, microseconds
```

Review `bench/results/BENCHMARK.md`, then copy its content into the repository's
top-level `BENCHMARK.md`. That copy is deliberate: nothing writes numbers into
the repository automatically.

## Where to run it

**Not on a laptop, not in a VM, not under WSL.** The harness records the
governor and the virtualisation type and prints a warning, but it will not stop
you — recording the caveat is not the same as the numbers being usable. A
frequency-scaling laptop can vary by more between two runs of the same
configuration than a proxy hop costs.

Check the noise floor before reading anything else. If it is a large fraction of
the differences between configurations, the run says nothing and no amount of
repetitions will fix it.

## Useful flags

| Flag | Purpose |
|---|---|
| `--check` | Verify prerequisites and exit |
| `--configs direct haproxy prism_plain` | Subset of configurations |
| `--workloads select` | One workload only |
| `--seed N` | Reproduce a previous run's configuration ordering |
| `--reps N` | Repetitions (default 3) |
| `--allow-short` | Permit sub-minimum durations. **Harness development only** — short runs do not settle and are not comparable to anything. |

## Design notes

**The noise floor is measured and printed first.** The baseline runs against
itself, changing nothing, and the spread across those runs is the resolution of
the whole experiment. Printing it before any result is what stops a reader
treating a 2% gap as a finding.

**Configurations are shuffled within each repetition.** A machine that warms up,
thermally throttles, or drifts over the course of an hour would otherwise
systematically favour whichever configuration always runs first. The seed is
recorded so an ordering can be reproduced.

**Warmup output is discarded, not averaged in.** Connection pools fill, caches
warm, and the JIT-free but still cold path settles. Thirty seconds is the
minimum and the harness refuses to run with less.

**Percentiles are nearest-rank, from per-transaction logs.** No interpolation, so
a reported p99 is a latency that actually occurred. `pgbench`'s own summary
latency average is not used. (The first version of this had an off-by-one that
reported p100 as p99; `test_harness.py` exists because of it.)

**`RUST_LOG=warn` for PG-Prism during runs.** At `info` it logs several lines per
connection, which under the `-C` workload would make this a benchmark of the
logger.

**No `guardian.yaml` is written.** Rule evaluation is a separate cost from
address injection, and mixing them makes the number impossible to attribute.

**PgBouncer runs without `send-proxy`,** because it cannot read a PROXY header
and hangs if sent one (`AUDIT.md` §15.2).

## The sanity assertion

Each configuration declares what it sits behind. A proxy cannot be faster than
what it forwards to, so if one measures faster by more than the noise floor, the
harness **fails the run**: non-zero exit, and the failure written into the output.

That is not a formality. It is the specific error this project already made
once — a committed notebook showed the proxy beating a direct connection, which
was impossible and went unquestioned. The assertion exists so that the same
mistake cannot be published twice.

When it fires, the answer is to find the measurement error: a service that did
not start, traffic that bypassed a hop, a warmup that leaked into a run. It is
never to relax the threshold.

```bash
python3 bench/test_harness.py    # 14 tests, mostly proving the assertion fires
```

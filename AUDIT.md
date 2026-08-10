# PG-Prism — Pre-Conference Codebase Audit

> **This document describes defects, some of which are not yet fixed.** It is a
> work list, not a description of the current code. See the *Remediation status*
> table below for what has been addressed and in which commit. For the current
> shipped behaviour and its limits, read the README.

**Audit date:** 2026-08-10 · **Commit:** `73ec20a` (branch `main`, clean tree)
**Target event:** PGDay Israel 2026, 2026-10-25 · **Slide deadline:** 2026-10-01
**Scope:** full repository — Rust core, Python core, docs, Docker/HAProxy config, benchmarks, committed artifacts.
**No code was changed in this pass.**

> Note on scope: the prompt refers to a *conference abstract*. No abstract is committed to this repository. Section 5 and 6 audit the README and the architecture guide only; **bring me the abstract text and I will re-run those two sections against it.**

---

## Executive summary — the things that would actually hurt you on stage

1. **Anyone who can reach port 5433 can forge the PROXY header and become any IP.** There is no trusted-proxy allowlist (`core/rust/src/main.rs:133`, `:172-186`). This spoofs `pg_stat_activity` *and* bypasses Guardian IP rules. The PostgreSQL core patch you'll be compared against solved this on day one with `proxy_servers`. A core contributor will ask this.
2. **Query cancellation is broken.** `CancelRequest` (80877102) is unhandled; the packet is fed through `inject_ip_startup` and corrupted (`main.rs:245-250`, `:299`, `:417-421`). Ctrl-C in psql does not work through the proxy.
3. **The rewriter corrupts legitimate queries.** `SELECT * FROM pg_settings WHERE name = 'application_name' AND setting = 'x'` gets mangled into a syntax error (`main.rs:472-495`). So does `set_config('application_name', ...)`.
4. **Unauthenticated remote panic, 4 bytes.** `00 00 00 04` after the PROXY header panics on `payload[0..4]` (`main.rs:419`). Plus a UTF-8 boundary panic in the 63-byte truncation (`main.rs:99`) — exactly the bug you suspected. Both confirmed.
5. **README and the architecture guide state opposite TLS behaviour.** The guide is right: the proxy terminates TLS with a self-signed cert and talks **plaintext** to PostgreSQL (`main.rs:116`, `:209-214`, `:291`). `sslmode=verify-full` cannot work; `scram-sha-256-plus` is never offered.
6. **Guardian is bypassed by ~1 KB of padding** (`main.rs:330`), by uppercase (`SELECT * FROM SECRETS`, `guardian.rs:161`), and **entirely by IPv6 clients** (`guardian.rs:83-87`).
7. **`application_name` is not an audit control.** `RESET application_name;` passes through untouched (`main.rs:466`, no quotes → no rewrite). Say this before someone else does.
8. **The talk is about HA and the sidecar is an unmonitored SPOF.** `listener.accept().await?` exits the whole process on `EMFILE` (`main.rs:146`); the README's health check probes Patroni on 8008, not the sidecar (`README.md:138` vs `haproxy.cfg:16`).
9. **The repo is not presentable.** 706 files of `core/rust/target/` (~95 MB), a 2.5 MB committed Linux binary, a screenshot, and an **AI chat transcript** (`Implement PG-Prism Guardian.md`). All need a history rewrite.
10. **Zero tests, zero CI.** No `#[test]`, no `tests/`, no `.github/`. For a wire-protocol proxy, this is the first thing a reviewer checks.
11. **The committed notebook shows the proxy *faster* than direct PostgreSQL** (`pg_prism_test.ipynb`, cell 14). Never show that slide.

---

## 1. Repository inventory

### 1.1 Source

| Path | Purpose | Verdict |
|---|---|---|
| `core/rust/src/main.rs` (581 L) | Rust core: PROXY parse, TLS, startup rewrite, Q/P rewrite, bidirectional pump | Source. Primary deliverable. |
| `core/rust/src/guardian.rs` (182 L) | Rule engine: YAML rules, connection match, query substring match | Source. |
| `core/rust/Cargo.toml` | 11 dependencies | Source. `bytes = "1"` (line 8) appears **unused** — no `bytes::` reference in either source file. Remove. |
| `core/rust/Cargo.lock` | Lockfile | Correct to commit for a binary crate. Keep. |
| `core/rust/guardian.yaml` | Example rules | Source/config. Not copied into the image (see 6.4). |
| `core/python/main.py` (534 L) | Python core — the **documented default** (`README.md:128`) | Source. Diverges materially from Rust (see 5.4). |

### 1.2 Documentation

| Path | Purpose | Verdict |
|---|---|---|
| `README.md` | English, user-facing | Contains the TLS contradiction (`:19`) and a wrong health check (`:138`). |
| `PG_PRISM_ARCHITECTURAL_GUIDE.md` | Turkish, 13.7 KB, deep-dive | Technically the more accurate document, but **it is in Turkish** and the audience is at an English-language conference. Section 8 (`:297-303`) is addressed *"to future AI models"* — delete before this is public. |
| `LICENSE` | MIT | Fine. |

### 1.3 Deployment / test harness

| Path | Purpose | Verdict |
|---|---|---|
| `Dockerfile` | Two-stage Rust build + Python runtime | Source, but see 6.4 — `guardian.yaml` is never copied in, and `ENV CORE_TYPE=python  ` (`:25`) has trailing whitespace before a stray comment line. |
| `docker-compose.yml` | postgres + pg-prism + haproxy | Source. Hardcoded `POSTGRES_PASSWORD=test123` (`:11`) — demo-only, but flag it in the README. |
| `haproxy.cfg` | 5434 → pg-prism:5433 `send-proxy` | Source. **No `check` directive at all** (`:16`). |
| `benchmark.py` | 10× `psql -c "SELECT 1"` subprocess loop, hardcoded port 5001 (`:24`) | **Leftover.** Measures process spawn, not the proxy. Delete. |
| `pro_benchmark.py` (12.8 KB) | Hand-rolled async PG client, SCRAM, 50 conns × 5 s × 10 iters | Source, genuinely useful — but it measures a hand-written client, not a real driver. Keep as a smoke test, do not benchmark with it (see §10). |
| `requirements.txt` | "no external dependencies" comment only | Keep, or delete — it contains no requirements. |

### 1.4 Must not be in version control

| Path | Size | Why | History rewrite? |
|---|---|---|---|
| `core/rust/target/**` | **706 files, ~95 MB** of loose objects incl. a 44 MB `libtokio*.rlib` and a 33 MB `.pdb` | Build artifacts. `.gitignore` has no `target/` entry. | **Yes** — added in `0e714ab`. |
| `pg-prism-rust` | 2.5 MB | Compiled Linux binary at repo root | **Yes** — added in `00e4494` (first commit). |
| `Screenshot From 2026-02-15 19-40-59-EDIT.jpg` | 89 KB | Screenshot, referenced by nothing | **Yes** — `00e4494`. |
| `Implement PG-Prism Guardian.md` | 8 KB | **Raw AI chat transcript.** Opens `# Chat Conversation`, contains your Turkish prompts, `/opt/pg-prism` paths, and a log of every file the assistant opened. | **Yes** — `e4ede12`. Highest embarrassment-per-byte in the repo. |
| `pg_prism_test.ipynb` | 724 KB | Colab notebook **with outputs committed**, including implausible benchmark results (see §10.1) and a `git clone https://github.com/heyobi/pg-prism.git` | **Yes** — `73ec20a` (HEAD). |

**No secrets, keys, or certificates are tracked** (`git ls-files | grep -Ei '\.(p12|crt|key|pem)$'` → empty). But the runtime *generates* `server.crt`, `server.key`, `identity.p12` into the working directory (`main.rs:25-27`) and `.gitignore` does not exclude them — one careless `git add .` publishes a private key.

**Recommended `.gitignore` additions:** `target/`, `*.p12`, `*.crt`, `*.key`, `*.pem`, `*.ipynb`, `prism.log`, `haproxy.log`.

**History rewrite:** everything above is in past commits, so `git rm` alone is insufficient. With 11 commits and (I assume) no external forks, the cleanest path is `git checkout --orphan` → single clean initial commit → force-push, rather than `git-filter-repo`. Do this **before** the repo is publicised, not after.

---

## 2. Correctness and robustness findings

Line-by-line on the Rust core, which is what people will read.

### 2.1 UTF-8 boundary panic in the 63-byte truncation — CONFIRMED

```rust
// main.rs:98-102
let truncated_name = if original_name.len() > available_len {
    &original_name[..available_len]        // <-- panics
```

`main.rs:99`. `available_len` is a **byte** count derived from `NAMEDATALEN`, and `&str[..n]` panics unless `n` is a char boundary. Reachable from three call sites with fully client-controlled input:

- `main.rs:442` — `application_name` from the StartupMessage
- `main.rs:488` — `SET application_name` in a simple query
- `main.rs:529` — same in a Parse message

**Trigger:** connect with `application_name` = 60 bytes of any multi-byte text (Turkish `ğ`, Hebrew, emoji, a Cyrillic hostname) and an IPv4 client IP. `available_len = 63 - 15 = 48`; if byte 48 lands mid-character, `panic: byte index 48 is not a char boundary`.

**Correct fix** (do not use `.chars().take()` — that changes semantics from bytes to chars and can still exceed 63 bytes):
```rust
let mut end = available_len.min(original_name.len());
while end > 0 && !original_name.is_char_boundary(end) { end -= 1; }
&original_name[..end]
```

Note `main.rs:96-97` (`available_len == 0` → `suffix[..max_len]`) is **dead code**: the longest possible suffix is `" - "` + a 45-char IPv6 literal = 48 bytes < 63. It is also itself a panic waiting to happen if the IP source ever changes. Delete it.

The Python core has the same *shape* (`core/python/main.py:69`) but Python slices by code point, so it does not crash — it silently produces a value longer than 63 bytes for non-ASCII names, which PostgreSQL then truncates itself. **The two cores do not agree.**

### 2.2 Out-of-bounds panic on a 4-byte startup packet — CONFIRMED

`main.rs:252-256` breaks out of the negotiation loop when `payload.len() < 4`. `main.rs:299` then calls `inject_ip_startup(&payload, …)`, whose first statement is:

```rust
// main.rs:419
new_payload.extend_from_slice(&payload[0..4]);   // panics on empty payload
```

**Trigger, unauthenticated, 4 bytes after the PROXY header:**
```
PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n \x00\x00\x00\x04
```
`payload_len = 4 - 4 = 0` → `read_exact` of nothing succeeds → break → panic. Note `main.rs:291` has already opened an upstream TCP connection to PostgreSQL by then, so each attempt also churns a backend connection.

### 2.3 Unbounded allocation from an attacker-supplied length — CONFIRMED

```rust
// main.rs:195-197
let msg_len = u32::from_be_bytes(len_bytes);
let payload_len = (msg_len.saturating_sub(4)) as usize;
payload.resize(payload_len, 0);              // up to 4 GiB, before reading a single byte
```

Also at `main.rs:220-221` inside the TLS branch. PostgreSQL itself caps the startup packet at 10000 bytes (`MAX_STARTUP_PACKET_LENGTH`). Nothing here does. `N` connections × `0xFFFFFFFF` = OOM-kill of the sidecar, i.e. of the whole data path.

### 2.4 Unbounded PROXY header read — CONFIRMED

```rust
// main.rs:171-172
let mut proxy_header = Vec::new();
buf_reader.read_until(b'\n', &mut proxy_header).await?;
```

No length limit, **no timeout**. A client that opens a socket and dribbles bytes without ever sending `\n` holds a task and grows a `Vec` forever. Classic slowloris + memory amplification. PROXY v1 headers are ≤ 107 bytes by spec; cap at 108 and use `tokio::time::timeout`.

Also: PROXY **v2** (binary) is not supported at all — `read_until(b'\n')` on the binary signature `\r\n\r\n\0\r\nQUIT\n` will return a partial/garbage line that fails the `starts_with("PROXY")` check at `main.rs:175`. HAProxy's `send-proxy-v2` is a very common configuration. Say "v1 only" in the README (it does, `README.md:16` — good) and consider adding v2.

### 2.5 Partial reads

Mixed. The **length-prefixed paths are correct**: `read_exact` is used at `main.rs:194`, `:198`, `:218`, `:222`, `:326`, `:332`, `:372`. Your instinct about single-read assumptions is not borne out here.

**But** there are two real problems:

**(a) Buffered bytes are discarded on every `into_inner()`.** `BufReader` may have read ahead into its 8 KB buffer; `into_inner()` throws that buffer away. This happens at `main.rs:207`, `:224`, `:228`, `:238`, `:247`. Any bytes the client pipelined after the message being parsed are **silently lost**. Well-behaved clients wait for `S`/`N` and for the auth request, so this is latent rather than firing today — but it is a bug a reviewer will spot instantly, and it will fire the moment a client pipelines. Use `BufReader::into_parts()`/`buffer()` and re-prepend, or `Chain` the residue.

**(b) A partial read inside blind-forwarding desyncs the stream instead of terminating it:**
```rust
// main.rs:369-375
while left > 0 {
    if client_reader.read_exact(...).await.is_err() { break; }   // breaks INNER loop only
    ...
    left -= chunk_len;
}
```
`main.rs:372` and `:373` break the `while left > 0` loop, then fall through to `main.rs:377` and the **outer** loop, which reads the next byte as a message type — from the middle of a message body. The connection then forwards garbage to PostgreSQL instead of closing. Use a labelled break or propagate the error.

### 2.6 Panics reachable from a per-connection task

Every panic listed above fires inside the `tokio::spawn` at `main.rs:154`. Tokio catches it as a `JoinError`, so **the process survives** — but the `JoinHandle` is dropped unchecked at `main.rs:154-158`, so:

- nothing is logged (the `if let Err(e) = handle_client(...)` at `:155` never runs — the panic unwinds past it),
- the client socket is dropped mid-handshake → **bare TCP RST, no `ErrorResponse`**,
- the upstream socket opened at `main.rs:291` is dropped too.

So a panic looks, from the client, exactly like a network fault. That is the worst possible failure mode for a debugging tool. Minimum fix: wrap the body in `AssertUnwindSafe(...).catch_unwind()` and emit an `ErrorResponse` + log before dropping.

### 2.7 Missing timeouts, backpressure, fd leaks

- **No timeout anywhere in the codebase.** Not on the PROXY read, not on the TLS handshake (`main.rs:212` — a client that completes TCP but never sends a ClientHello pins a task forever), not on the upstream connect (`:291`), not on idle connections.
- **No connection limit.** `main.rs:145-158` spawns without a semaphore. No `max_client_conn` equivalent.
- **The accept loop kills the process on error.** `main.rs:146`: `let (client_socket, _) = listener.accept().await?;` — the `?` propagates out of `main`. `EMFILE`/`ENFILE` under fd pressure **terminates the proxy**, taking every established connection with it. For an HA talk this is the finding. Log-and-continue with a backoff.
- **Half-close is never propagated, so connections leak.** `main.rs:399`: `tokio::try_join!(client_to_server, server_to_client)`. Both futures return `Ok(())` unconditionally, so `try_join!` degenerates to `join!` — it waits for **both**. When the client disappears, `client_to_server` breaks but `server_to_client` blocks on an idle backend read forever. Two fds and one task leak per event, until the OS TCP timeout (hours, given `timeout client 30m`/`timeout server 30m` in `haproxy.cfg:8-9`). Under connection churn this is a slow fd exhaustion that then trips the accept-loop bug above. Use `tokio::select!` and call `shutdown()` on the peer.
- **Backpressure exists only incidentally** via `write_all` on an 8 KB buffer. `main.rs:377` flushes on **every message**, and `main.rs:394` flushes on **every 8 KB read** from the backend — combined with `set_nodelay(true)` (`:147`, `:292`) that is a syscall per packet in both directions. Correct for latency, but do not call it zero overhead.

### 2.8 `application_name` edge cases (as asked)

| Case | Behaviour | Verdict |
|---|---|---|
| **Absent** from StartupMessage | `main.rs:451-457` appends it. But `format_application_name("", ip)` returns `" - 1.2.3.4"` and `trim_start_matches(" -")` strips only `" -"`, leaving **`" 1.2.3.4"` with a leading space** (`main.rs:455`). | Bug, cosmetic but visible in every `pg_stat_activity` row of the demo. Python core writes the bare IP (`main.py:469`) — **cores disagree**. |
| **Already at 63 bytes** | Truncated to `available_len` then suffixed → exactly 63 bytes. Correct **if ASCII**; panics if the cut lands mid-character (2.1). | Partial. |
| **`options` parameter present** | Not inspected at all — `main.rs:440` only matches the key `application_name`. A client connecting with `options=-c application_name=spoofed` passes straight through. | **Gap.** Whether `-c` wins over the startup parameter is *unverified* — resolve by connecting with both set and reading `pg_stat_activity`. Either way the proxy makes no attempt. |
| **Duplicate `application_name` keys** | Rust rewrites *every* occurrence (`main.rs:440` inside the loop). Python builds a `dict` (`main.py:444`) so it **silently drops duplicates and reorders all parameters**. | Cores disagree; Python's reordering is a protocol-visible behaviour change. |
| **Client `SET`s it after handshake** | Attempted interception (§5.2) — bypassable several ways. | **Not a security control.** |

### 2.9 Error path: backend unreachable mid-handshake — CONFIRMED BAD

`main.rs:291`: `let pg_socket = TcpStream::connect(pg_addr).await?;`

On failure the `?` returns `Err` from `handle_client`, which is logged as `"Connection dropped: …"` (`main.rs:156`) and the client socket is dropped. **The client receives a FIN with no `ErrorResponse`** — psql prints `server closed the connection unexpectedly`, JDBC throws a generic `SocketException`. You have all the machinery to do better: `make_error_response(…, "08006")` already exists at `main.rs:68`. Same applies to the Guardian DENY path, which *does* do the right thing (`main.rs:278-284`) — so the inconsistency is glaring.

### 2.10 Guardian logic bugs

| Finding | Location | Detail |
|---|---|---|
| **IPv6 clients bypass every rule** | `guardian.rs:83-87` | `"0.0.0.0/0".parse::<IpCidr>()` **succeeds**, so the `else if cidr_str == "0.0.0.0/0"` fallback at `:85` is unreachable. `cidr.contains(&v6_addr)` is false → the catch-all rule never matches an IPv6 client → falls through to the default `INSPECT` with **empty** block lists (`:132`) → all query filtering silently off. |
| **Unparseable IP → DENY** | `guardian.rs:68-72` | Fails closed, which is correct — but combined with `main.rs:181` (`parts.nth(2)`) a malformed PROXY line yields a confusing 28000 rejection rather than a clear diagnostic. |
| **Overnight time ranges never match** | `guardian.rs:103-111` | String comparison: `"22:00-06:00"` requires `t >= "22:00" && t <= "06:00"`, impossible. Maintenance-window rules silently do nothing. Python has the identical bug (`main.py:172`). |
| **Substring matching, case-sensitive for tables** | `guardian.rs:161`, `:177` (`memmem::find`) | `block_tables: ["secrets"]` blocks `SELECT * FROM secrets` but **not** `SELECT * FROM SECRETS` — and PostgreSQL folds unquoted identifiers, so they are the same table. Also bypassed by `U&"secret\0073"`. |
| **Substring matching, false positives for commands** | `guardian.rs:152-157` | `block_queries: ["DROP"]` blocks `SELECT * FROM eavesdropping` and `SELECT 'droplet'`. `block_tables: ["secrets"]` blocks `-- secrets`. |
| **A blocked Parse desyncs the extended protocol** | `main.rs:336-345` | On block the proxy sends `ErrorResponse` + `ReadyForQuery` and `continue`s (`:344`), keeping the connection open. Correct for `'Q'`. **Wrong for `'P'`**: the backend never saw the Parse, but the client then sends `Bind`/`Describe`/`Execute`/`Sync`, which *are* forwarded — the backend replies `unnamed prepared statement does not exist` and the two ends disagree about state. Also, sending `ReadyForQuery` mid-extended-query-sequence is itself a protocol violation; the client should get `ErrorResponse` and then have its `Sync` answered. |
| **Rules are loaded once at startup** | `main.rs:111` | No reload, no `SIGHUP`. Fine, but say so. |
| **Config parse failure = allow-all** | `main.rs:111-114`, `guardian.rs:57-60` | A typo in `guardian.yaml` **silently disables the firewall** and logs a `warn!`. A security control must fail closed or refuse to start. |
| **Python's YAML parser is a regex** | `main.py:82-112` | Hand-rolled; handles only `key: [a, b]` inline lists. Any block list (`- item` on its own line) is silently dropped → rules quietly weaken. Not "zero-dependency", just undertested. |

---

## 3. Protocol conformance checklist

| Message | Direction | Handling | Verdict |
|---|---|---|---|
| **PROXY v1** | C→P | `main.rs:172-186`. Reads to `\n`, `split(' ')`, `nth(2)`. | **Partial.** No trusted-source check (§5.1), no length cap, no timeout, accepts bare `\n`, ignores the family field (`TCP4`/`TCP6`/`UNKNOWN`), no v2. |
| **PROXY v2** | C→P | Not implemented. | **Missing.** `send-proxy-v2` deployments break at `main.rs:175`. |
| **SSLRequest** (80877103) | C→P | `main.rs:204-235`. Replies `S` and terminates TLS, or `N` when disabled. | **Correct**, with caveats — buffered-byte discard at `:207`/`:228`, and the README describes the wrong branch. |
| **GSSENCRequest** (80877104) | C→P | `main.rs:236-243`. Replies `N`, loops. | **Correct.** Refusal is the right answer for a proxy that cannot relay GSSAPI. |
| **StartupMessage** (196608) | C→P | `main.rs:267-288`, rewritten at `:299`/`:417-461`. | **Partial.** Only 3.0 (196608) is recognised. A client negotiating **3.1/3.2** (`196609`/`196610`, PG 18+) falls into the `_` arm at `main.rs:245` → `context_initialized` stays false → **Guardian connection rules are silently skipped entirely** while the payload is *still* rewritten by `inject_ip_startup`. libpq 18 currently defaults to 3.0 via `max_protocol_version`, so this is a forward-compatibility landmine rather than a live bug — *unverified against a real PG 18 client; resolve by connecting with `max_protocol_version=3.2`.* |
| **NegotiateProtocolVersion** | S→C | Blind-forwarded. | Fine (it is in the S→C byte pump). |
| **CancelRequest** (80877102) | C→P, **second connection** | **Not handled.** Not in the constants at `main.rs:10-12`. Falls to `_` at `:245`, then `inject_ip_startup` at `:299` treats the 12-byte body (`code`+`pid`+`key`) as null-separated parameters, splits it on stray zero bytes, and appends `application_name\0 <ip>\0\0`. | **WRONG — and the most demo-visible defect.** The forwarded packet has a new length and corrupted content; PostgreSQL rejects it. **Ctrl-C in psql, `Statement.cancel()` in JDBC, and every admin cancel path silently fail through the proxy.** The fix is one match arm: recognise 80877102 and forward the 16 bytes verbatim, skipping injection. Guardian must also skip it (a CancelRequest carries no user/db). |
| **Query** (`Q`) | C→P | `main.rs:330-363`, rewritten by `process_simple_query` (`:465`). | **Partial/dangerous.** Inspected only when `payload_len < 1024`; the rewriter corrupts legitimate SQL (§5.3). |
| **Parse** (`P`) | C→P | `main.rs:348-352`, `process_extended_query` (`:505`). | **Partial.** Same 1 KB cliff; block path desyncs (§2.10). Correctly preserves the parameter-type tail (`:540`) — credit where due. |
| **Bind / Describe / Execute / Sync / Close** | C→P | Blind-forwarded (`main.rs:364-376`). | Correct as pass-through, but it means the *value* in `SELECT set_config('application_name', $1, …)` is never seen. |
| **CopyData / CopyDone** | C→P | Blind-forwarded. | Correct. |
| **Terminate** (`X`) | C→P | Blind-forwarded. | Correct. |
| **ErrorResponse** (`E`) | P→C | Synthesised at `main.rs:68-86`. | **Partial.** Fields `S`, `C`, `M` only. The protocol requires a **`V`** (non-localised severity) field for protocol ≥ 3.0 clients, and PostgreSQL always sends it. Some drivers log warnings; none that I know of hard-fail — *unverified*. Add `V`. |
| **ReadyForQuery** (`Z`) | P→C | `main.rs:341`, hardcoded `Z\0\0\0\x05I`. | **Correct bytes, wrong assumption.** Always claims `I` (idle) even if the session is inside a transaction, where the truthful answer is `T` (or `E` after the error). A blocked query inside a transaction leaves the client believing it is out of one. |
| **ParameterStatus** (`S`) | P→C | Blind-forwarded, never rewritten. | **Consistent** — the backend reports the *injected* `application_name`, so the client sees `"DBeaver - 10.0.0.5"`. Arguably correct; call it out as deliberate. |
| **Authentication\*** / **BackendKeyData** | P→C | Blind-forwarded. | Correct, and this is why plain SCRAM works (§4). |
| **SCRAM-SHA-256-PLUS** | both | Never offered by the backend (plaintext leg). | See §4. |

---

## 4. TLS behaviour, resolved

**The README is wrong; the architecture guide is right.**

Evidence: `SSL_ENABLED` defaults to `"true"` (`main.rs:116`); `load_tls_acceptor()` shells out to `openssl` to mint a self-signed `CN=localhost` certificate and a PKCS#12 with the hardcoded password `"mypassword"` (`main.rs:33-51`, `:63`); on `SSLRequest` the proxy answers `S` and runs `acceptor.accept(raw_socket)` (`main.rs:209-214`). The `N`/plaintext branch at `main.rs:227-233` runs **only** when TLS initialisation failed or `SSL_ENABLED=false`. The upstream connection at `main.rs:291` is a bare `TcpStream` and **no `SSLRequest` is ever sent to PostgreSQL**.

`README.md:19` — *"SSL Handling: Forces plaintext connection (by handling SSLRequest) to allow packet inspection"* — describes the fallback path as if it were the default. Rewrite it.

Two operational notes: the p12 password is hardcoded in the source (`main.rs:49`, `:63`) — harmless in itself since the key sits unencrypted next to it, but it will be read as sloppy; and generating the cert by `Command::new("openssl")` at startup (`main.rs:33`) means the runtime image must ship the `openssl` **CLI**, which the final stage of the `Dockerfile` never explicitly installs (it is installed only in the builder, `Dockerfile:3`). *Unverified whether `python:3.12-slim` includes `/usr/bin/openssl`; resolve with `docker run --rm python:3.12-slim which openssl`.* If it does not, TLS silently falls back to plaintext in the shipped image — which would explain the README.

### The three sentences for the stage

> PG-Prism terminates TLS itself, using a self-signed certificate it generates at startup, and speaks **plaintext** to PostgreSQL on the loopback or pod-local leg.
>
> That means `sslmode=verify-full` will fail unless you deploy your own certificate and distribute its CA to clients, and because PostgreSQL sees an unencrypted connection it never advertises `SCRAM-SHA-256-PLUS` — plain `scram-sha-256` works unchanged, but any client with `channel_binding=require` cannot connect.
>
> This is the deliberate trade: PG-Prism is a sidecar you run on the database host, so the unencrypted leg never leaves the machine — if that is not true in your topology, do not deploy it.

That last clause is the honest one, and it is also your answer to the hostile version of the question. **Verify the `channel_binding=require` claim empirically before you say it** — I have read the code path, not run the client.

---

## 5. Security claims audit

### 5.1 UNSTATED CLAIM, AND THE MOST SERIOUS FINDING: the PROXY header is trusted unconditionally

Neither document claims the client IP is *trustworthy*, but every use of it — `pg_stat_activity` attribution, Guardian's `ips:` rules — presumes it. It is not.

`main.rs:133` binds `0.0.0.0` by default. `main.rs:172-186` reads and trusts whatever line arrives. There is **no allowlist of source addresses permitted to send a PROXY header.**

Concrete exploit against the repo's own shipped configuration:

```
$ printf 'PROXY TCP4 127.0.0.1 127.0.0.1 1 2\r\n' | cat - startup_as_postgres.bin | nc <host> 5433
```
`guardian.yaml:2-5` grants `127.0.0.1/32` + user `postgres` the `ALLOW` action, which `guardian.rs:137-139` short-circuits to *bypass every query rule*. So one forged line disables Guardian **and** writes a false client IP into the audit trail.

This is precisely the problem `proxy_servers` solves in the PostgreSQL core PROXY patch, and it is the first thing a reviewer from that world will look for. **Fix before the repo is public:** a `TRUSTED_PROXIES` CIDR list checked against the real peer address from `listener.accept()` (currently discarded — `main.rs:146` binds the `SocketAddr` to `_`), refusing the connection when it does not match.

### 5.2 "Smart Lightweight Filter … only small Query/Parse packets (< 1KB)" — CONFIRMED BYPASS

`README.md:17` presents this as a performance feature. It is also a complete authorisation bypass.

`main.rs:330`: `if (msg_type == b'Q' || msg_type == b'P') && payload_len < 1024`. The `else` branch (`:364-376`) forwards blind — no Guardian check, no rewrite.

**Threshold, exactly:** `payload_len = msg_len - 4`, and a `Query` payload is `query_text + '\0'`. Inspection is skipped when `payload_len >= 1024`, i.e. when the query text is **≥ 1023 bytes**. So:

```sql
DROP TABLE secrets; --<1000 spaces>
```
1022 characters of padding is enough. Or `/* <1000 bytes> */ DROP TABLE secrets;`. Cost to the attacker: one kilobyte. Every `block_queries` and `block_tables` rule is bypassed, and so is the `SET application_name` interception in §5.3.

**Honest replacement for `README.md:17`:**
> *Query inspection is applied to Query and Parse messages under 1 KB. This is a latency optimisation, not a security boundary — larger statements are forwarded without inspection, so Guardian rules are advisory and must not be relied on as an authorisation control.*

### 5.3 `application_name` as an audit control — REFUTED, and the rewriter is actively harmful

**Bypasses of the `SET` interception** (`main.rs:465-501`):

| Technique | Why it works |
|---|---|
| `RESET application_name;` | `contains_ignore_case_ascii(payload, b"set")` matches the `SET` inside `RESET` (`:466`), `application_name` is found (`:472`) — but there are **no single quotes**, so `:477` finds nothing and the statement is forwarded verbatim. The value resets to the client's original, un-injected startup value. |
| `SET application_name TO $$evil$$;` | Dollar quoting — no `'`, no rewrite. |
| `SET application_name = 'x'` padded past 1023 bytes | §5.2. |
| `SELECT set_config('application_name', $1, false)` via extended protocol | The value is in the `Bind` message, which is blind-forwarded. |
| Any statement where the IP already appears in the value | `main.rs:486` skips the rewrite if the value contains the IP substring — so `SET application_name = 'innocent 1.2.3.4 spoof'` is left alone. |

**And the rewriter corrupts valid SQL.** `main.rs:472-495` finds the first literal `application_name` anywhere in the payload — including inside string literals and comments — then rewrites whatever sits between the next two single quotes:

```sql
-- input, a perfectly ordinary query:
SELECT * FROM pg_settings WHERE name = 'application_name' AND setting = 'x'
-- what PostgreSQL actually received (observed, not predicted):
SELECT * FROM pg_settings WHERE name = 'application_name' AND setting =  - 203.0.113.99'x'

-- and for set_config, a straight syntax error:
SELECT set_config('application_name', 'reporting', false)
SELECT set_config('application_name',  - 203.0.113.99'reporting', false)
```

*(The exact mangling above is corrected from the original audit, which predicted
the shape of the corruption from reading the code. The strings here are what
`tests/query_passthrough.rs` captured at the backend before the rewriter was
deleted. The conclusion is unchanged.)*
The first quote found after `application_name` is its own **closing** quote. Same failure for `SELECT set_config('application_name','v',false)`, which becomes a syntax error. Any application that reads its own GUCs, logs a query containing the word, or stores it in a table is broken by the proxy. `process_extended_query` (`:505-550`) has the identical flaw.

This is a **data-plane correctness bug**, not just a security one, and it is the sort of thing that shows up as a mystery outage three weeks after deployment.

**Honest replacement:**
> *PG-Prism sets `application_name` at connection time, so it is accurate for connections that never change it. A client can overwrite or reset it at any point after the handshake; `application_name` is a debugging aid, not an audit control. Use `log_line_prefix`/`pgaudit` for anything that must be trustworthy.*

And I recommend you **delete the post-handshake `SET` rewriting entirely** before October. It cannot be made correct without a real SQL lexer, it breaks legitimate queries today, and removing it deletes ~90 lines, two of the three UTF-8 panic sites, and the whole "but I can just `SET` it back" line of attack — you get to answer that question with *"correct, and I don't pretend otherwise"* instead of defending a leaky filter.

### 5.4 "Zero overhead" / "zero allocation" / "zero dependencies" / "feature parity" — ALL REFUTED

`PG_PRISM_ARCHITECTURAL_GUIDE.md:13-15`.

**"Zero external dependencies"** — `Cargo.toml` lists 11 direct dependencies including `tokio` with `features = ["full"]` (the whole runtime, not the parts used) and `native-tls`, which links **OpenSSL**. `bytes` is declared and unused. The Python core *is* stdlib-only, so scope the claim to Python.

**"Near-zero allocation per connection and query"** — per *connection*: `Box<dyn AsyncReadWrite>` (`main.rs:189`, `:214`, `:248`), `Vec::new()` for the PROXY header (`:171`), a `Vec<&[u8]>` of parameter parts (`:426`), a `String::from_utf8_lossy` **per parameter key and value** (`:432-433`) plus two more in `extract_user_db` (`:566-567`), three `format!`s in `format_application_name` (`:89`, `:92`, `:103`), an `Arc<Mutex<_>>` (`:308`), and two 8 KB buffers (`:307`, `:316`). Per *query*: `Vec::with_capacity` on every rewrite (`:490`, `:531`, `:536`).

**"Zero parsing overhead"** — `contains_ignore_case_ascii` (`main.rs:407-410`, `guardian.rs:172-175`) is a naive `windows().any()`, O(n·m) with no SIMD, run over every sub-1 KB query for every needle. `guardian.rs` imports `memchr::memmem` and then uses it for **only one** of its two search functions (`:180` vs `:174`).

**"Zero overhead"** also has to survive `main.rs:392`: a `tokio::sync::Mutex` **acquired on every 8 KB chunk** from the backend, plus a `flush()` (`:394`) on each. The architecture guide (`:137-163`) presents this mutex as an elegant borrow-checker solution; it is a per-write lock on the hot path that exists only because the design chose to let the C→S task write to the client. A `mpsc` channel to a single writer task, or simply not synthesising errors from the C→S side, removes it.

**"Feature parity — both cores run identical rules and produce identical protocol output"** (`guide:15`) — false in at least six ways: absent-`application_name` value (`" 1.2.3.4"` vs `1.2.3.4`); non-ASCII truncation (panic vs silent over-length); parameter ordering (preserved vs dict-reordered); duplicate parameter keys (kept vs dropped); blocked-query behaviour (connection stays open vs `break`s the loop — `main.rs:344` vs `main.py:262`); and `LISTEN_HOST`/`LISTEN_PORT`, which the Python core **hardcodes and ignores** (`main.py:10-11`) despite being documented as configurable (`README.md:124-125`) and set by the Dockerfile (`Dockerfile:20-21`).

**Honest replacement:**
> *The Rust core is built on tokio and allocates a small, bounded amount per connection; inspection is limited to sub-1 KB Query and Parse messages so bulk traffic is forwarded without parsing. Measured overhead is X µs at p99 (see benchmarks). The Python core is a reference implementation for readability and is not feature-identical.*

(Fill in X from §10. Do not put a number on a slide you have not measured on hardware you can describe.)

---

## 6. Documentation versus code contradictions

| # | Topic | README | Architecture guide | Code | Truth |
|---|---|---|---|---|---|
| 1 | **TLS** | "Forces plaintext connection" (`:19`) | "SSL sonlandırır (TLS Termination)" (`:30`, `:61`) | Terminates TLS, default on (`main.rs:116`, `:209-214`) | **Guide.** README is wrong. |
| 2 | **Topology** | `Client → HAProxy → PG-Prism → Postgres`, no ports (`:23-28`) | Client:5434 → HAProxy → 5433 → PG-Prism → 5432 (`:19-37`) | `haproxy.cfg:12` binds 5434, `:16` → `pg-prism:5433`; `main.rs:134` listens 5433, `:141` → 5432 | **Guide + haproxy.cfg agree.** README should state the ports. |
| 3 | **Health check** | `server pg01 10.0.0.1:5433 check port 8008 send-proxy` (`:138`) | Not mentioned | — | **Both wrong for the purpose.** `haproxy.cfg:16` has **no `check` at all**; port 8008 is Patroni's REST API, which reports on *PostgreSQL*, not the sidecar. See §8. |
| 4 | **Guardian in Docker** | `docker run … pg-prism` with no volume (`:41-56`) | Shows the compose volume mount (`:277-278`) | `Dockerfile` never `COPY`s `guardian.yaml`; `main.rs:111` falls back to allow-all with a `warn!` | **Following the README's quickstart silently disables Guardian.** Copy a default `guardian.yaml` into the image. |
| 5 | **Default core** | `CORE_TYPE` default `python` (`:128`), and `Dockerfile:25` agrees | Shows `CORE_TYPE=rust` (`:273`) | `docker-compose.yml:23` uses `rust` | Inconsistent. Pick Rust as the default — the Python core has known divergences. |
| 6 | **`LISTEN_HOST`/`LISTEN_PORT`** | Documented as configurable (`:124-125`) | — | Rust honours them (`main.rs:133-134`); **Python hardcodes them** (`main.py:10-11`) | README is wrong for the core it declares to be the default. |
| 7 | **`SSL_ENABLED`** | **Not documented at all** | — | `main.rs:116`, `main.py:16` | Missing from the config table. So are `SSL_CERT_PATH`/`SSL_KEY_PATH` (`main.py:17-18`), which the Rust core **ignores** (it hardcodes `server.crt`/`server.key`/`identity.p12`, `main.rs:25-27`). |
| 8 | **Dependencies** | badges: Python 3.12, Rust 1.80 (`:8-9`) | "Zero external dependencies … only tokio, native-tls, serde" (`:13`) | `Dockerfile:2` uses **Rust 1.85**; `Cargo.toml` has 11 deps | Three-way disagreement. |
| 9 | **PROXY version** | "Native support for HAProxy `PROXY v1`" (`:16`) | v1 (`:48-53`) | v1 only, `main.rs:172` | **Consistent and correct.** Keep the explicit "v1 only". |
| 10 | **1 KB filter** | "zero parsing overhead" feature (`:17`) | — | `main.rs:330` | Correct as described, but the security consequence is undocumented (§5.2). |
| 11 | **Audience/language** | English | **Entirely Turkish**, and §8 (`:297-303`) is addressed to future AI models | — | Translate or unpublish the guide before October 1. |

### 6.1 Canonical architecture description — rewrite all three against this

> **PG-Prism** is a per-host sidecar proxy for PostgreSQL that restores client identity lost behind a TCP load balancer.
>
> **Topology.** Clients connect to HAProxy (default `:5434`, `mode tcp`). HAProxy forwards to PG-Prism on the database host (`:5433`) with `send-proxy`, prefixing a PROXY protocol **v1** header. PG-Prism reads that header, extracts the original client address, and opens a **plaintext** connection to PostgreSQL on `:5432` — a loopback or pod-local hop that must not cross a network boundary.
>
> **What it does to the connection.** PG-Prism answers `SSLRequest` itself and terminates TLS with its own certificate (self-signed by default; supply your own for `verify-ca`). It answers `GSSENCRequest` with `N`. It parses the StartupMessage and rewrites `application_name` to `"<original> - <client ip>"`, truncated to PostgreSQL's 63-byte `NAMEDATALEN` limit, adding the parameter if absent. All authentication messages are relayed verbatim, so `scram-sha-256` works unchanged; `scram-sha-256-plus` is not available because the backend leg is unencrypted.
>
> **Guardian.** An optional rule engine (`guardian.yaml`, first-match-wins) evaluated at connection time against client IP, user, database and time-of-day, yielding `ALLOW` / `INSPECT` / `DENY`. Under `INSPECT`, `Query` and `Parse` messages **smaller than 1 KB** are substring-matched against blocked commands and table names; matches are answered with a synthetic `ErrorResponse`. Larger messages and all other message types are forwarded without inspection. **Guardian is a guard rail, not an authorisation boundary.**
>
> **Trust boundary.** PG-Prism must only be reachable from the load balancers permitted to set the PROXY header; anyone who can open a TCP connection to its listener can assert an arbitrary client IP. *(Write this only once the allowlist from §5.1 exists — until then the sentence is "must be firewalled to the load balancer".)*
>
> **Not implemented:** PROXY v2, `CancelRequest` pass-through *(fix before the talk)*, connection pooling, load balancing, failover, protocol versions other than 3.0.

---

## 7. Prior art positioning

This must be defensible against the people who wrote these tools. Where I am summarising rather than citing code I have read, I say so.

| Tool | How it addresses client identity | Where it stops |
|---|---|---|
| **PgBouncer `application_name_add_host`** | Added in 1.6, default `off`; appends the client host and port to `application_name`, e.g. `192.168.1.100:12345`. | **This is your closest competitor and you must lead with it.** It works only if PgBouncer *is* the thing that terminates the client connection — if HAProxy sits in front of PgBouncer, PgBouncer sees HAProxy's IP and dutifully records the wrong address. It is also documented as overridable by a client `SET` (the same limitation you have, §5.3). PgBouncer does not read the PROXY protocol. |
| **HAProxy `send-proxy` / `send-proxy-v2`** | Preserves the true client address on the wire, correctly and cheaply. | HAProxy can *send* it; **PostgreSQL cannot read it.** The backend sees a startup packet prefixed with a line it does not understand and closes the connection. The entire gap PG-Prism fills is "something must consume that header before PostgreSQL sees it." This is your strongest framing. |
| **PostgreSQL core PROXY protocol patch** (Magnus Hagander, first posted March 2021, CF entry 36/3032) | The correct, in-core solution: a `proxy_servers` GUC listing trusted CIDRs, after which the real address populates `pg_hba.conf` matching, `log_line_prefix %h`, **and** `pg_stat_activity.client_addr` — the actual column, not a string smuggled through `application_name`. | It has been in the commitfest process for years and, to my knowledge, **is not committed as of PG 18**. *Unverified for the current cycle — check `commitfest.postgresql.org/36/3032/` and the latest thread the week before the talk; if it lands in PG 19 you need to know before you walk on stage.* You should cite this patch approvingly and position PG-Prism as "what you can run on PostgreSQL 13–18 today, until this lands." Do **not** position yourself as an alternative to it. Note also that the patch's `proxy_servers` design is exactly what §5.1 says you are missing — adopt the same model and name. |
| **`log_line_prefix` with `%h`** | Zero-cost, built in, correct — for the address PostgreSQL actually sees. | Behind any L4 proxy `%h` is the proxy's address. It is also log-only: nothing lands in `pg_stat_activity`, so you cannot answer "who is running this query *right now*". |
| **pgcat** | Rust pooler with sharding, load balancing, failover. | *I could not confirm PROXY protocol support from the sources I read — verify against the repo before asserting anything.* Positioning-wise, it is a **pooler**: it terminates the client session and multiplexes onto server connections, so per-client attribution is fundamentally harder, and adopting it is a much larger architectural change than adding a sidecar. |
| **Odyssey** | Yandex's multithreaded pooler; strong per-client logging with client IDs. | Same class as pgcat — *PROXY protocol support unverified*. Same argument: you are asking for a sidecar, not a pooler swap. |
| **`pg_stat_statements` / `pgaudit`** | Query attribution and auditing. | Neither recovers a client address that the backend never learned. |

**The one-paragraph positioning to say on stage:**

> HAProxy already knows the real client address and can send it — that part is solved. PostgreSQL cannot read it, and the in-core patch that would fix that has been in review since 2021. PgBouncer's `application_name_add_host` covers the case where PgBouncer is your only proxy; it does not help when HAProxy is in front. PG-Prism is a stop-gap for the specific topology of HAProxy in front of PostgreSQL on versions that ship today: a sidecar that consumes the PROXY header and puts the address somewhere you can see it. When the core patch lands, delete it.

That last sentence buys you enormous credibility with this audience, and it costs you nothing.

---

## 8. Single point of failure analysis

The talk is about high availability. The sidecar is in the connection path with none of the properties an HA component needs.

### 8.1 Failure modes

| Event | Established connections | New connections | Detected? |
|---|---|---|---|
| **Sidecar killed (`SIGKILL`)** | All die immediately — every session is proxied through a process-local task, and there is no state anywhere else. Clients get RST mid-query. | Refused (`ECONNREFUSED`). | Only implicitly: HAProxy's `haproxy.cfg:16` has no `check`, so it discovers the failure per-connection and returns an error to the client each time. |
| **Sidecar restarted (systemd `Restart=always`, `RestartSec=5`, `README.md:95-96`)** | All die. There is no graceful drain, no `SIGTERM` handler — `main.rs` installs none. | Refused for ~5 s, then served. | No. |
| **Sidecar hangs** (fd exhaustion, OOM pressure, a task deadlocked on the write mutex at `main.rs:392`) | Stall silently. `haproxy.cfg:8-9` sets `timeout client/server 30m`, so a hung session sits there for **half an hour**. | Accepted by the kernel backlog, then never serviced — **worse than a crash**, because TCP connect succeeds. | **No.** This is the dangerous one. |
| **Sidecar OOM-killed** (§2.3 / §2.4) | All die. | Refused. | No. |
| **fd exhaustion** (§2.7 leak) | Survive, briefly. | `accept()` returns `EMFILE`, the `?` at `main.rs:146` propagates, **`main` returns and the process exits**. | Turns a degradation into a total outage. |

### 8.2 Does the health check topology detect a dead sidecar?

**No, and the README's version is actively harmful.**

`haproxy.cfg:16` is `server pg_prism pg-prism:5433 send-proxy` — no `check`. HAProxy never probes; it simply fails each connection attempt.

`README.md:138` suggests `check port 8008`, i.e. the Patroni REST API. That probe reports on **PostgreSQL's** health. A sidecar that is hung or crashed while Patroni happily returns 200 is marked **UP**, and HAProxy keeps routing every connection into a black hole. The documented configuration is strictly worse than no check at all, because it manufactures false confidence — and it is the configuration a Patroni-using audience will recognise and copy.

There is also no second sidecar anywhere in the repo: one `server` line, one container. No redundancy exists to fail over *to*.

### 8.3 Minimum change that makes this defensible

Three items, roughly a day of work, and they turn the weakest part of the talk into a slide:

1. **Make the check probe the sidecar's own listener.** Delete `check port 8008`. Use `server pg_prism pg-prism:5433 check send-proxy inter 2s fall 2 rise 2` — a TCP check against 5433 detects "crashed" and "not accepting", which covers most of the table above.
2. **Add a real liveness endpoint** — a second `TcpListener` on `:8009` returning `200 OK` only if the accept loop has ticked recently, plus `check port 8009`. This is the only thing that detects **hang**, which is the failure mode that hurts. ~40 lines.
3. **Fix `main.rs:146` to log-and-continue with a backoff instead of `?`,** so fd pressure degrades instead of terminating.

Then, for the talk, say the honest thing: *"One sidecar per database host, so its blast radius is exactly the blast radius of the database it sits next to. If the sidecar dies, that node is out — which is the same event Patroni already handles by failing over. It does not add a **new** single point of failure; it widens an existing one."* That argument is sound **only** once the health check actually detects the sidecar, so item 1 is a hard prerequisite for the claim.

---

## 9. Testing and CI gap

### 9.1 What a reviewer expects and does not find

- No `#[cfg(test)]`, no `#[test]` — zero, in either source file.
- No `core/rust/tests/` integration directory.
- No `.github/` — **no CI at all.** Nothing runs `cargo build`, `cargo clippy`, `cargo fmt --check`, or `cargo audit`.
- No Python tests, no linting, no type checking.
- No fuzz target, despite the project being a parser of untrusted network input.
- No `docker compose up && run tests` smoke script.
- No `SECURITY.md`, `CONTRIBUTING.md`, or `CHANGELOG.md`.
- `Cargo.toml` has no `[profile.release]` tuning and the binary is built without `--locked` in CI (there is no CI).

For a 700-line wire-protocol proxy, the absence of a single test is the most common reason a reviewer closes the tab. It is also the cheapest thing on this list to fix, because the parsing functions are already pure.

### 9.2 Minimal suite that proves protocol correctness

**Tier 1 — pure unit tests, no I/O (half a day, and it catches four confirmed bugs).**
`format_application_name`, `inject_ip_startup`, `process_simple_query`, `process_extended_query`, `extract_user_db`, and `Guardian::check_query` are all pure functions. Table-drive them:

| Test | Catches |
|---|---|
| `format_application_name("ğ"×30, "10.0.0.5")` | §2.1 UTF-8 panic |
| `format_application_name("", ip)` — assert no leading space | §2.8 |
| assert every output is `≤ 63 bytes` **and** valid UTF-8 | the class of bug, not the instance |
| `inject_ip_startup(&[], ip)` | §2.2 slice panic |
| `inject_ip_startup` on a 16-byte CancelRequest | §3 CancelRequest corruption |
| `process_simple_query("SELECT * FROM pg_settings WHERE name='application_name' AND setting='x'")` — assert **unmodified** | §5.3 query corruption |
| `process_simple_query("RESET application_name;")` | §5.3 bypass, documents the limitation |
| `check_query(b"SELECT * FROM SECRETS", …)` with `block_tables=["secrets"]` | §2.10 case bypass |
| `check_connection("2001:db8::1", …)` against a `0.0.0.0/0` rule | §2.10 IPv6 bypass |
| `check_connection` with `time_range: "22:00-06:00"` | §2.10 midnight bug |

**Tier 2 — fuzzing the StartupMessage parser (half a day).**
`cargo-fuzz` target over `inject_ip_startup` + `extract_user_db`, and a second over `process_simple_query`. Invariants: never panic; output is a well-formed sequence of NUL-terminated pairs terminated by a double NUL; the length prefix matches the body; the first 4 bytes are unchanged. Run 10 million iterations once and put "fuzzed, N iterations, zero panics" on a slide — this audience respects that far more than a TPS number.

**Tier 3 — partial-read and protocol integration tests (one to two days).**
A test harness that speaks the wire protocol over an in-memory duplex (`tokio::io::duplex`) or a real socket, driving `handle_client` against a mock backend:

1. **Partial read / byte-at-a-time:** feed the PROXY header and StartupMessage **one byte per `write`, with a yield between each**, and assert the backend receives a correct rewritten packet. Repeat with every possible split point. This is the test the audience will ask about; it is also the test that will find bugs you do not know about yet.
2. **Coalesced read:** PROXY header + SSLRequest + StartupMessage in a **single** `write` — this is the test that fails today because of the `into_inner()` buffer discard (§2.5a).
3. **CancelRequest round trip:** open a session, capture `BackendKeyData`, open a *second* connection, send a CancelRequest, and assert the mock backend receives the **16 bytes verbatim**.
4. **Truncated / malformed startup:** length 0, length 4, length `0xFFFFFFFF`, non-NUL-terminated parameters, odd parameter count, empty keys. Assert no panic, bounded allocation, and a clean `ErrorResponse`.
5. **Backend refuses connection:** assert the client receives an `ErrorResponse` with SQLSTATE `08006`, not a bare FIN (§2.9).
6. **Guardian block over the extended protocol:** Parse → blocked → Bind → Sync, and assert the connection state is coherent (§2.10).
7. **1 KB boundary:** a query at 1022 and at 1024 bytes containing a blocked keyword; assert *both* are blocked — this test **fails today** and encodes the §5.2 decision either way.
8. **End-to-end against real PostgreSQL** in CI services: connect via psql and via the JDBC driver, assert `SELECT application_name FROM pg_stat_activity WHERE pid = pg_backend_pid()` equals the expected string, for ASCII, non-ASCII, absent, and over-long names.

### 9.3 Proposed CI workflow

`.github/workflows/ci.yml`, four jobs:

- **`check`** — `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo build --locked --release`. Clippy alone will flag several things in §2.
- **`test`** — `cargo test --locked`, plus `ruff` and `mypy` (or at minimum `python -m compileall`) on `core/python/`.
- **`integration`** — `services: postgres:15`, run Tier 3 tests plus a `docker compose up` smoke check that the demo path in §11 actually works. This job is what stops the demo breaking the night before.
- **`audit`** — `cargo audit` and `cargo deny check`, weekly on a schedule. `native-tls`/OpenSSL makes this non-optional.

Add a `fuzz` job on a weekly cron with a short time budget; nightly fuzzing in PR CI is overkill.

---

## 10. Benchmark methodology

### 10.1 Discard everything currently in the repo

- `benchmark.py` spawns `psql` in a subprocess ten times (`:10-15`). It measures **process creation and TCP connect**, dominated by fork/exec. It also targets port 5001, which nothing in this repo listens on (`:24`). Delete.
- `pro_benchmark.py` is a decent hand-rolled client, but benchmarking your proxy with your own minimal client invites "you wrote both sides." Keep it as a protocol smoke test; do not present numbers from it.
- **`pg_prism_test.ipynb` must not be cited.** Cell 12's committed output reports 281.88 TPS direct versus a *higher* figure through HAProxy+PG-Prism, and cell 14's 50-iteration table opens `222.80` direct / `282.08` through the full proxy chain. A proxy cannot be faster than no proxy; that is noise from a shared Colab VM (177–195 ms average latency at those TPS figures confirms a heavily contended host). If you show it, someone will do that arithmetic out loud.

### 10.2 The benchmark to run

**Environment (one dedicated machine, everything on it, no cloud):** this is a per-host sidecar, so co-locating is the honest configuration and it removes network variance.

**Four arms, identical in every other respect:**

| Arm | Path | Purpose |
|---|---|---|
| A | `pgbench → PostgreSQL:5432` | Absolute floor. |
| B | `pgbench → HAProxy:5434 → PostgreSQL:5432` | **The real baseline.** Isolates HAProxy's cost so PG-Prism's delta is not credited with it. Most people skip this; do not. |
| C | `pgbench → HAProxy:5434 → PG-Prism:5433 → PostgreSQL:5432` | The product. |
| D | `pgbench → PgBouncer:6432 → PostgreSQL:5432` | PgBouncer in **session** pooling mode with `application_name_add_host=1` — the closest existing solution (§7). |

Report **C − B** as "the cost of PG-Prism". Reporting C − A and calling it your overhead is the mistake that gets caught.

**Workloads — run both:**
- **`-S` (select-only)**, the latency-sensitive case where proxy overhead is proportionally largest. This is the honest hard case; lead with it.
- **`-N` (simple-update, no vacuum)** as a realistic mixed case.
- **Connection-establishment micro-benchmark** with `-C` (reconnect per transaction) at low concurrency. This is where PG-Prism's cost actually lives — the startup rewrite is per-connection, the steady-state path is a byte pump — and showing it separately demonstrates you understand your own system.

**Parameters:**
```
pgbench -i -s 100 …                                   # ~1.5 GB, larger than shared_buffers
pgbench -S -c {1,8,16,32,64,128} -j 8 -T 60 -P 10 --progress-timestamp \
        --latency-limit=10000 -M extended …
```
- **`-M extended`** — matters, because it exercises the `Parse` path (`main.rs:348`) that JDBC and every modern driver use. Also run `-M simple` for the `Query` path. `-M prepared` is worth one run: after the first Parse, statements arrive as Bind/Execute, which PG-Prism forwards blind — it should show near-zero overhead and that is a *good* result to be able to explain.
- **Warmup:** one discarded 60 s run per arm, then `pg_prewarm` the pgbench tables, then three measured 60 s runs. Report the **median run**, and the spread across the three.
- **Duration:** 60 s measured. Shorter is noise; longer does not help at this scale.
- **Concurrency sweep** to 128 — the interesting slide is overhead *versus* concurrency, because the per-write mutex (`main.rs:392`) and the per-message flush (`:377`) should show up as the curve diverging. If it does not diverge, that is a real finding you can claim.

**What to report:** TPS, and latency **p50 / p95 / p99 / max**. `pgbench` gives you mean and stddev directly; get true percentiles by adding `--log --log-prefix=` and computing them from the per-transaction log — do not present a mean and call it p99. Also report the **absolute delta in microseconds**, not only a percentage: "adds 40 µs at p99" is a far stronger claim than "3% slower", and it does not collapse when someone points out your baseline query is trivially cheap.

**What must appear on the slide** (put it in small type in the corner of the results slide, and say "all of this is in the repo"):
CPU model, core count, whether SMT/turbo/C-states are on, RAM, kernel version, distro; PostgreSQL version and every non-default `postgresql.conf` setting (`shared_buffers`, `max_connections`, `fsync`, `synchronous_commit`, `checkpoint_timeout`); HAProxy version and config; PgBouncer version, pool mode, and pool size; PG-Prism commit SHA and `--release` build with the exact `rustc` version; pgbench scale factor and full command line; the loopback/UNIX-socket distinction for each arm; number of runs and which statistic is shown; and whether the client ran on the same host.

**One thing that will be asked and that you should pre-empt:** run one arm with `pgbench` on a *separate* machine over a real NIC. On loopback, proxy overhead is maximally visible relative to a near-zero network cost; over a real network it shrinks to irrelevance. Showing both is the honest presentation and it happens to flatter you.

**Also measure and report memory and fd count per connection** at 128 connections (`/proc/<pid>/status`, `ls /proc/<pid>/fd | wc -l`). Given §2.7, run one arm for ten minutes with connection churn (`-C`) and check whether the fd count returns to baseline. Know the answer before someone else runs it.

---

## 11. Demo plan — 5 minutes, fully offline

**Pre-provision the night before:** `docker compose build` and `docker pull postgres:15-alpine haproxy:2.8-alpine` so no image is fetched on the day. Verify with the laptop's network **physically off**. Pre-create the pgbench data. Pre-open every terminal, pre-type every command, font size ≥ 18 pt.

**Layout:** two panes side by side. Left = the client. Right = a live `watch` on `pg_stat_activity`. The right pane is the payoff and it must be visible the whole time.

**Beat 0 — before you start talking (already running, not part of the 5 minutes):**
```bash
docker compose up -d
# Right pane, running from the start:
watch -n1 'docker exec pg-prism-postgres psql -U postgres -tAc \
  "SELECT pid, client_addr, application_name, state FROM pg_stat_activity WHERE backend_type='"'"'client backend'"'"'"'
```

**Beat 1 (~60 s) — the problem.** Connect *bypassing* the sidecar, straight through a plain HAProxy backend to PostgreSQL:
```bash
PGPASSWORD=test123 psql -h 127.0.0.1 -p 5435 -U postgres -c "SELECT pg_sleep(30)" &
```
Right pane shows `client_addr = 172.x.x.x` — the HAProxy container. Point at it: *"That is my load balancer. Every one of my four hundred application servers looks like this row."*
*(This requires a second HAProxy backend on 5435 pointing directly at postgres:5432. Add it to `haproxy.cfg` — it does not exist today.)*

**Beat 2 (~60 s) — the fix.** Same command through the PG-Prism path:
```bash
PGPASSWORD=test123 psql -h 127.0.0.1 -p 5434 -U postgres \
  -c "SET application_name='invoicing-worker'; SELECT pg_sleep(30)" &
```
Right pane gains a row reading `invoicing-worker - 10.x.x.x`. Two rows side by side, one useless, one actionable. **That is the whole talk in one screen.** Do not rush past it — let it sit for ten seconds in silence.

**Beat 3 (~90 s) — Guardian.**
```bash
PGPASSWORD=test123 psql -h 127.0.0.1 -p 5434 -U postgres -c "DROP TABLE secrets;"
# ERROR:  Query blocked by PG-Prism Guardian
```
Then immediately, and this is the beat that wins the room:
```bash
PGPASSWORD=test123 psql -h 127.0.0.1 -p 5434 -U postgres \
  -c "DROP TABLE secrets; $(python3 -c 'print("--"+" "*1050)')"
# succeeds
```
*"One kilobyte of whitespace. That is why I call it a guard rail and not a firewall — and it is in the README in those words."* Volunteering your own bypass, on stage, before anyone finds it, converts your weakest section into your most credible moment. **Do this only if §5.2 is documented honestly in the repo by then** — otherwise it reads as a confession rather than a design decision.

**Beat 4 (~60 s) — failure.**
```bash
docker kill pg-prism-sidecar
PGPASSWORD=test123 psql -h 127.0.0.1 -p 5434 -U postgres -c "SELECT 1"   # fails
docker start pg-prism-sidecar && sleep 3
PGPASSWORD=test123 psql -h 127.0.0.1 -p 5434 -U postgres -c "SELECT 1"   # works
```
Pre-empts the SPOF question by answering it yourself with a live demonstration (§8).

**Recovery paths, in order of preference:**
1. **A pre-recorded `asciinema` cast of the exact same sequence**, in a terminal tab that is already open. If anything stalls for more than ten seconds, switch to it and narrate over the top. Record it the week before, in the room's resolution. This is non-negotiable — record it even if you never use it.
2. **Screenshots of each of the four beats** as slides at the end of the deck, so you can jump to them if the terminal is entirely dead.
3. **`docker compose down -v && docker compose up -d`** as a hard reset — but only if you have ≥ 2 minutes left, and know your startup time to the second.
4. A `demo/reset.sh` in the repo that tears down, restarts, and re-verifies in one command. Write it, and run the full demo end-to-end from a cold boot at least five times before the 25th, including once on the venue's projector resolution.

**Hard rules:** aeroplane mode on. No `docker build` on stage. No copy-paste from a browser or a PDF. Every command in a `demo/` shell script with numbered functions so you type `beat2` rather than a 90-character psql line. Disable shell autocomplete surprises and clear your history. Have `secrets` and the pgbench tables pre-created — a demo that fails because a table does not exist is the worst way to lose a room.

---

## 12. Hostile Q&A — 20 questions, most likely first

**1. "The client can just `SET application_name` back. So what is this actually worth?"**
Correct, and it is documented as a limitation. It is a debugging aid, not a security control — it tells you which of your four hundred app servers is running the query that is pinning your CPU right now, which is a question `log_line_prefix` cannot answer live. If you need an untamperable answer, you need the in-core PROXY patch or `pgaudit`, not this.

**2. "Why not just use PgBouncer's `application_name_add_host`?"**
If PgBouncer is your only proxy, use it — it is better tested and I would not deploy this instead. It stops working the moment something else, HAProxy in my case, sits in front of PgBouncer, because then PgBouncer records HAProxy's address. PG-Prism reads the PROXY header, which is the piece PgBouncer does not do.

**3. "What happens when the sidecar dies? You have put a new SPOF in front of my database."**
Every established connection dies; new ones are refused until it restarts. It is one sidecar per database host, so its blast radius equals that of the PostgreSQL instance beside it — Patroni already fails over on that event. But I will be straight with you: the health check in my repo today probes Patroni, not the sidecar, so a *hung* sidecar goes undetected. That is a bug and it is on my list.

**4. "Doesn't this break TLS? What does `sslmode=verify-full` do?"**
It fails, unless you supply your own certificate and distribute its CA. The proxy terminates TLS with a self-signed cert by default and talks plaintext to PostgreSQL over loopback. If your threat model includes the loopback interface on the database host, do not deploy this.

**5. "Then channel binding is dead."**
Plain `scram-sha-256` works because I relay the auth messages verbatim. `scram-sha-256-plus` is never offered, because PostgreSQL only advertises it on its own TLS connections and my backend leg is plaintext. Anyone using `channel_binding=require` cannot connect through it. That is a real cost and I would not hide it.

**6. "What stops me sending my own PROXY header and claiming to be 127.0.0.1?"**
Nothing, today, and that is the most serious bug in the project. The in-core patch got this right with a `proxy_servers` allowlist and I need the same thing. Until then the listener must be firewalled to the load balancer, and I should not have shipped it binding `0.0.0.0` by default.

**7. "Does `CancelRequest` work? Ctrl-C in psql?"**
No. It opens a second connection with a different startup packet that I do not recognise, and I currently corrupt it. It is a small fix — recognise 80877102 and forward sixteen bytes untouched — and it is the first thing I am fixing.

**8. "You say zero allocation. Is it?"**
No, and I should not have written that. There is a boxed trait object per connection, a `String` per startup parameter, a mutex acquired on every write to the client, and a flush per message. I am rewriting that claim to a measured microsecond figure.

**9. "Why not wait for the in-core PROXY protocol patch?"**
You should, if you can. It has been in review since 2021 and I could not wait on PostgreSQL 15 in production. When it lands, this becomes obsolete and that is a good outcome — it puts the address in `client_addr`, where it belongs, instead of smuggling it through a string.

**10. "Guardian blocks on substring matching. I can bypass it in five seconds."**
You can bypass it in one: pad the statement past a kilobyte and it is not inspected at all. It is a guard rail against accidents, not an authorisation boundary — that is what roles and `REVOKE` are for. I document it that way and I would rather say so than let you find it.

**11. "What is the latency cost?"**
[X µs at p99 on the select-only workload, measured against a bare HAProxy baseline, not against a direct connection.] The cost is concentrated in connection setup, because after the handshake it is a byte pump. Full methodology and hardware are in the repo. — *Do not answer this until §10 has been run.*

**12. "What PostgreSQL versions and protocol versions?"**
Protocol 3.0 only. Anything negotiating 3.1 or 3.2 falls through a path that skips my connection rules entirely — a bug I found preparing this talk, not yet fixed. PostgreSQL 13 through 18 on the 3.0 default.

**13. "Have you fuzzed the parser?"**
Not yet, and for a parser of untrusted network bytes that is the right question to be embarrassed by. I have confirmed two panics by reading the code — a UTF-8 boundary in the 63-byte truncation and an out-of-bounds slice on a four-byte packet — and a `cargo-fuzz` target is the next thing I write.

**14. "What is your test coverage?"**
Zero at the time of this talk. The parsing functions are pure and trivially testable, which makes it inexcusable rather than difficult. There is a test plan in the repo and the unit tier lands before this is recommended to anyone.

**15. "It is 63 bytes, not 63 characters. What happens with a Hebrew or Turkish application name?"**
It panics, and the connection dies with a TCP reset and no error message. Confirmed, fixed by walking back to a character boundary. Good question to ask at a conference in Tel Aviv.

**16. "Why `application_name` and not the `options` parameter, or a custom GUC?"**
`application_name` is visible in `pg_stat_activity` and `log_line_prefix %a` with no configuration, which was the point. A custom GUC via `options=-c` would be cleaner and would not collide with what the client wanted to say — I did not do it, and I do not currently inspect `options` at all, so a client can set `application_name` through that door.

**17. "How do you handle connection pooling? Do sessions get reused?"**
I do not pool. One client connection maps to exactly one backend connection for its whole life. Put PgBouncer behind me if you need pooling — though note that then the pooler's reuse breaks per-client attribution again, which is a genuine unsolved interaction I have not worked through.

**18. "What happens under connection churn? Do you leak file descriptors?"**
Today I wait for both directions of the pump to finish, and I do not propagate half-close, so a client that disappears while the backend is idle leaks a task and two descriptors until the TCP timeout. And if I then hit `EMFILE`, my accept loop propagates the error and the process exits. Both are on the must-fix list.

**19. "Does it handle PROXY protocol v2?"**
No, v1 only. `send-proxy-v2` will not work. v2 is binary and length-prefixed, so it is actually the easier one to parse correctly — I should support it.

**20. "Would you run this in production?"**
Not in its current state, and I would rather say that here than have you find out. It is a working demonstration of an idea, with a list of known defects I have just walked you through. The idea — consume the PROXY header in a sidecar — I stand behind; this implementation needs the fixes on that slide first.

---

## 13. Prioritized plan — 2026-08-10 → 2026-10-01 (slides) → 2026-10-25 (event)

Roughly seven weeks to the slide deadline. The binding constraint is not the code, it is that **you cannot write honest slides about behaviour you have not yet fixed or measured.** Sections 4, 5, 10 and 12 all depend on decisions made in the next three weeks.

### Tier 1 — Must fix before the repository is public-facing (~5 days)

| # | Item | Effort |
|---|---|---|
| 1.1 | **History rewrite.** Orphan commit; drop `target/`, `pg-prism-rust`, the screenshot, `Implement PG-Prism Guardian.md`, `pg_prism_test.ipynb`, `benchmark.py`. Extend `.gitignore`. | 2 h |
| 1.2 | **Trusted-proxy allowlist** (§5.1). `TRUSTED_PROXIES` CIDR list checked against the real peer address; default to loopback-only. | 4 h |
| 1.3 | **Fix both panics** (§2.1, §2.2) — char-boundary walk, length guards on every slice. | 3 h |
| 1.4 | **`CancelRequest` pass-through** (§3). One match arm. | 1 h |
| 1.5 | **Bound the inputs** (§2.3, §2.4) — cap startup length at 10000, cap the PROXY header at 108 bytes, add timeouts to the PROXY read, TLS handshake, and upstream connect. | 4 h |
| 1.6 | **Fix the accept loop** (§2.7) — log-and-continue with backoff. | 1 h |
| 1.7 | **Delete the post-handshake `SET` rewriting entirely** (§5.3). Removes ~90 lines, the query-corruption bug, and one whole line of hostile questioning. | 2 h |
| 1.8 | **Rewrite the README against the canonical description** (§6.1): TLS truth, ports, `SSL_ENABLED`, the 1 KB caveat in the words from §5.2, the `application_name`-is-not-an-audit-control paragraph, a "Known limitations" section, and a "Not production ready" banner. | 4 h |
| 1.9 | **Fix the health check** (§8.3 items 1 and 3) and add the direct-to-postgres HAProxy backend the demo needs. | 2 h |
| 1.10 | Guardian: IPv6 catch-all, case-insensitive table matching, midnight ranges, **fail closed on config parse error** (§2.10). | 4 h |

### Tier 2 — Must be done before the slides are written (by ~2026-09-20) (~7 days)

| # | Item | Effort |
|---|---|---|
| 2.1 | **Tier 1 + Tier 2 tests and the fuzz target** (§9.2). Directly supplies answers to Q13 and Q14. | 2 d |
| 2.2 | **CI workflow** (§9.3) — a green badge is worth a paragraph of prose to this audience. | 4 h |
| 2.3 | **Run the benchmark** (§10) on hardware you can describe. Everything in Q11 and the results slide depends on this. **Start this by 2026-09-01** — you will run it twice. | 2 d |
| 2.4 | **Empirically verify the three TLS sentences** (§4): `sslmode=verify-full`, `channel_binding=require`, and a packet capture proving the backend leg is plaintext. Never assert on stage what you have only read. | 4 h |
| 2.5 | **Fix half-close propagation** (§2.7) — `select!` + `shutdown()`. Removes the fd leak and makes the churn benchmark defensible. | 3 h |
| 2.6 | **`ErrorResponse` on backend-unreachable** (§2.9), and add the `V` field to `make_error_response`. | 2 h |
| 2.7 | **Translate the architecture guide to English**, delete §8 ("notes for future AI models"), correct the TLS section. Or **unpublish it** — see the cut list. | 1 d |
| 2.8 | **Build and rehearse the demo** (§11) including the asciinema recording and `demo/reset.sh`. | 1 d |

### Tier 3 — Nice to have, only if Tiers 1–2 are genuinely finished

- Liveness endpoint on `:8009` (§8.3 item 2) — 4 h. *Promote to Tier 2 if you keep the HA framing as a major section, since Q3's answer is weaker without it.*
- PROXY v2 support — 1 d.
- Protocol 3.1/3.2 handling (§3) — 3 h.
- Remove the per-write mutex in favour of an mpsc writer (§5.4) — 1 d.
- Fix the `BufReader` buffer discard (§2.5a) — 4 h.
- `SIGTERM` graceful drain — 4 h.
- Connection limit semaphore — 2 h.

### Cut rather than rush

- **The Python core.** It is the documented default, it ignores `LISTEN_PORT`, it has a regex YAML parser that silently drops block-style lists, and it diverges from Rust in six observable ways. You cannot fix it *and* the Rust core by October. **Move it to `contrib/` or delete it, and remove the "dual core / feature parity" claim from both documents.** That deletes claim 5.4's hardest sub-claim and roughly a third of the audit surface for free. Half a day, and it makes everything else easier.
- **The architecture guide, if 2.7 does not fit.** Better absent than published in Turkish with a section addressed to AI models and a wrong TLS description. Fold the accurate parts into the README.
- **Any benchmark number you cannot reproduce twice.** If §10 does not finish cleanly by 2026-09-20, drop the performance slide entirely and say "I have not measured this rigorously enough to show you numbers." That sentence costs you thirty seconds. A number that someone recomputes in their head and finds impossible costs you the room — and the notebook currently in the repo contains exactly such a number.
- **Guardian as a headline feature.** It is the weakest code in the project and the easiest to attack. Demote it to a five-minute segment framed explicitly as a guard rail with a live self-demonstrated bypass (§11 beat 3). Do not build new Guardian features before October.

**Suggested checkpoints:** Tier 1 complete by **2026-08-24**. Benchmark started by **2026-09-01**. Tier 2 complete and outline drafted by **2026-09-20**. Slides frozen **2026-10-01**. Full dry run including demo, on the real laptop, by **2026-10-15**.

---

## Remediation status

Updated as work proceeds. Hashes refer to the rewritten history (see A1); every
hash from before the rewrite is dead.

| Finding | Status | Commit | Note |
|---|---|---|---|
| 1 — PROXY header trusted from any peer; client IP and Guardian IP rules spoofable | **fixed** | `11377ff` | New `TRUSTED_PROXIES` allowlist checked against the real TCP peer before the header is parsed; loopback-only default; fails closed on a malformed list and refuses to start. Reproduced first: `tests/trusted_proxy.rs` originally asserted that a forged header from an arbitrary peer was honoured, and passed. |
| 52 — **new, found in CI**: PostgreSQL escapes non-ASCII `application_name` to hex before applying NAMEDATALEN, so the injected address was truncated away | **fixed** | `b1c3ad4` | Observed on the first real-PostgreSQL run. Not reproducible against the fake backend, which stores whatever it is handed. Truncation now budgets in stored characters. |
| 2 — `CancelRequest` unhandled and corrupted | **reproduced, not yet fixed** | — | CI: `the query was never cancelled: it outlived the timeout`. A4. |
| 3 — the `SET` rewriter corrupts legitimate SQL | **fixed** | `6e69b30` | Deleted, not repaired. Reproduced first: `tests/query_passthrough.rs` captured the mangled statements at the backend. The audit's predicted example was wrong in detail and is corrected in §5.3. |
| 16 — `RESET` and dollar quoting bypass the interception | **removed** | `6e69b30` | The interception is gone, so the bypasses are moot. The limitation they pointed at (a client can always overwrite `application_name`) is now stated plainly and asserted by a test. |
| 44 — `bytes` dependency declared and unused | **fixed** | `36e29a3` | |
| 51b — no CI | **fixed** | `717b9aa` | fmt, clippy `-D warnings`, hermetic tests, real-PostgreSQL tests against a `postgres:16` service, and a Docker build. `cargo audit` runs weekly in its own workflow. |
| 10 — zero tests | **fixed** | `717b9aa`, and the suites added in A2/A3/A5 | 48 tests run locally (33 unit, 15 integration against the fake backend) plus 9 end-to-end tests against a real PostgreSQL in CI. |
| 4 — UTF-8 boundary panic in the 63-byte truncation | **fixed** | `13ff293` | Truncation steps back to the nearest char boundary. Reproduced first by sweeping suffix lengths across every alignment. |
| 5 — out-of-bounds panic on a 4-byte startup packet | **fixed** | `13ff293` | Guarded in `inject_ip_startup` and `extract_user_db`, and the caller now rejects the packet before either is reached. |
| 8 — `accept()` error terminates the process | **fixed** | `13ff293` | Logs and retries with exponential backoff capped at 1s. |
| 13 — unbounded allocation from a declared length | **fixed** | `13ff293` | Checked against PostgreSQL's own `MAX_STARTUP_PACKET_LENGTH` (10000) and a minimum of 8. |
| 14 — unbounded, untimed PROXY header read | **fixed** | `13ff293` | Capped at 108 bytes, the v1 specification maximum plus one. |
| 20 — no timeouts anywhere | **fixed** | `13ff293` | One deadline over the whole handshake, a separate one for the upstream connect. Tunable via `HANDSHAKE_TIMEOUT_SECS` / `UPSTREAM_CONNECT_TIMEOUT_SECS`; malformed values are a startup failure. |
| 47 — dead `available_len == 0` branch | **fixed** | `13ff293` | Removed; it was itself an unguarded slice. |
| 9 — build artifacts, binary, screenshot, AI transcript, notebook in history | **fixed** | `f3a5b91`, history rewrite | 79.45 MiB -> 50 KiB. Two commits (`e4ede12` "readmemd", `88a78e1` "testler basarili") contained nothing but removed content and were pruned as empty. |
| 27 — "feature parity" false; Python core ignores LISTEN_HOST/LISTEN_PORT | **removed** | `862f731` | Python core retired to `contrib/python/`; the claim is gone and the divergences are documented rather than denied. |
| 39 — Python regex YAML parser silently drops block lists | **removed** | `862f731` | Same. Documented in `contrib/python/README.md`. |
| 35 — runtime image may lack the `openssl` CLI | **fixed** | `862f731` | Base image is now `debian:bookworm-slim` with `openssl` installed explicitly instead of inherited by accident from `python:3.12-slim`. |
| 45 — Rust badge says 1.80, Dockerfile uses 1.85 | **fixed** | `862f731` | |
| 49 — `ENV CORE_TYPE=python  ` trailing whitespace | **removed** | `862f731` | Entrypoint switch deleted with the Python core. |
| 26 — "zero allocation / zero dependency / zero overhead" | **partially fixed** | `862f731` | The false claims are out of the architecture guide. The README rewrite (A7) and the measured figure (Phase B) are still outstanding. |
| 48 — `.gitignore` does not exclude generated key material | **fixed** | `f3a5b91` | |
| 51 — **new, not in the original audit**: committed `Cargo.lock` is stale; `cargo build --locked` fails | **fixed** | `89753a9` | The lock had no `native-tls`/`tokio-native-tls`/`openssl` entries despite Cargo.toml depending on them since the SSL commits. No build of this project was ever reproducible from the repository alone. Found because the Dockerfile now builds with `--locked`. |
| 43 — `benchmark.py` measures `psql` process spawn against a dead port | **removed** | history rewrite | Deleted from the working tree and from all history. |

---

## Evidence status

Every finding is one of three things. This matters because some of these will be
quoted on a conference slide.

- **Observed** — something was executed and produced the result quoted in this
  document. Safe to quote verbatim.
- **Inspected** — a fact about a file's contents, a configuration, or a git
  count. No execution needed; safe to quote, but it is a statement about the
  source, not about runtime behaviour.
- **Predicted** — inferred from reading the code and **not yet confirmed by
  running anything**. Do not quote as fact. Finding #3 was Predicted, turned out
  to be right in substance and wrong in detail, which is exactly the failure mode
  this column exists to prevent.

| # | Evidence | Basis |
|---|---|---|
| 1 | **Observed** | `tests/trusted_proxy.rs` originally asserted the broken behaviour and passed: the backend received `psql - 203.0.113.99` from a peer that was not a load balancer. |
| 2 | **Observed** | CI, real PostgreSQL: `the query was never cancelled: it outlived the timeout`. `pg_sleep(30)` ran to completion through the proxy. |
| 3 | **Observed** | `tests/query_passthrough.rs` captured the mangled statements at the backend. The audit's predicted mangling was wrong in detail; §5.3 now carries the observed strings. |
| 4 | **Observed** | `panicked at src/protocol.rs:42`, sweeping suffix lengths across every byte alignment. |
| 5 | **Observed** | `panicked at src/protocol.rs:67` on a four-byte startup packet, and `:219` for `extract_user_db`. |
| 6 | **Inspected** | Both documents read; `README.md:19` and the guide's section 1C state opposite things. The TLS behaviour itself is now **Observed** in CI. |
| 7 | Predicted | **Needs a test.** `large_queries_are_forwarded_intact` proves large messages skip inspection, but nothing yet drives a *blocked* statement through with padding. A6. |
| 8 | Predicted | Code fact that `?` propagates out of `main`; `EMFILE` was never actually induced. |
| 9 | **Inspected** | `git count-objects`: 79.45 MiB to 50 KiB; 706 tracked files under `target/`. |
| 10 | **Inspected** | No `#[test]`, no `tests/`, no `.github/` existed. |
| 11 | **Inspected** | `README.md:138` says `check port 8008`; `haproxy.cfg:16` has no `check` at all. Read, not executed. |
| 12 | Predicted | Not classified. |
| 13 | **Observed** | The bounds test hung until the proxy was fixed: the declared length was accepted and the read blocked. The 4 GiB allocation itself was not induced; 64 MiB was. |
| 14 | **Observed** | `oversized_proxy_header_is_refused` hung on 1 MiB with no newline. |
| 15 | Predicted | **Needs a test.** Code reading only: `0.0.0.0/0` parses successfully so the fallback branch is unreachable. A6 will add an IPv6 Guardian test. |
| 16 | **Observed** | `reset_application_name_reaches_postgres_unchanged` passed against the old code. |
| 17 | Predicted | **Needs a test.** `memmem::find` is case-sensitive by inspection; nothing drives `SELECT * FROM SECRETS` yet. A6. |
| 18 | Predicted | Code reading: `Guardian::new` returns `None` on a parse failure and the caller substitutes empty rules. |
| 19 | Predicted | **Needs a test.** `try_join!` waits for both directions by inspection; no descriptor-leak test exists. |
| 20 | **Observed** | Four bounds tests hung: silent client, stall after header, oversized length, oversized header. |
| 21 | Predicted | Code reading. A3 added a connect timeout but the bare close remains; A4 covers it. |
| 22 | Predicted | Explicitly unverified. Needs a client negotiating `max_protocol_version=3.2`. |
| 23 | Predicted | **Needs a test.** The desync follows from the message sequence, not from a run. A6. |
| 24 | Predicted | Code reading: the panic unwinds past the `if let Err` in the spawn body. |
| 25 | Predicted | Code reading: the inner `break` leaves work outstanding and falls through to the outer loop. |
| 26 | **Inspected** | The dependency count and the allocation sites are file facts. The **performance** half of the claim is unmeasured and stays Predicted until Phase B runs. |
| 27 | Predicted | Not classified. |
| 28 | Predicted | Code reading: `into_inner()` discards the buffer. Latent, because well-behaved clients do not pipeline at that point. |
| 29 | **Inspected** | No semaphore exists in the accept loop. |
| 30 | Predicted | **Needs a test.** String comparison cannot satisfy an overnight range, by inspection. A6. |
| 31 | Predicted | Explicitly unverified: the proxy does not inspect `options`, but whether `-c` beats the startup parameter was never tested. |
| 32 | Predicted | Code reading. The CI test asserts only that the address is present, not its exact form, so the leading space is still unconfirmed. |
| 33 | **Inspected** | v1 only, by inspection of the header parser. |
| 34 | **Inspected** | The `Dockerfile` contains no `COPY` of `guardian.yaml`. |
| 35 | **Inspected** | Was Predicted. Now partly settled: CI's `openssl version` step passes and the image installs it explicitly. Whether `python:3.12-slim` shipped it was never tested and no longer matters. |
| 36 | **Inspected** | Literal in `src/tls.rs`. |
| 37 | Predicted | **Needs a test.** The missing `V` field is a file fact; that no driver rejects the message is untested. |
| 38 | Predicted | Code reading: the ReadyForQuery payload is hardcoded to idle. |
| 39 | Predicted | Not classified. |
| 40 | Predicted | **Needs a test.** `DROP` matching `eavesdropping` follows from substring search. A6. |
| 41 | **Inspected** | The guide is in Turkish and its section 8 addresses AI models. |
| 42 | **Inspected** | No signal handler exists. |
| 43 | **Inspected** | `benchmark.py` targeted port 5001 and shelled out to `psql`. |
| 44 | **Observed** | Removed; the crate still builds. |
| 45 | **Inspected** | Badge says 1.80, Dockerfile says 1.85. |
| 46 | **Inspected** | Absent from the README table; the Rust core hardcodes the paths. |
| 47 | **Inspected** | The branch was unreachable by inspection; deleted. |
| 48 | **Inspected** | `.gitignore` contents. |
| 49 | **Inspected** | `Dockerfile:25` trailing whitespace. |
| 50 | **Inspected** | `docker-compose.yml:11` literal. |

**10 Observed, 19 Inspected, 21 Predicted.** The Predicted ones marked *Needs a test* are queued into A6 and A4.

---

## Findings table

Severity: **S1** = would materially damage credibility on stage or in the repo · **S2** = a reviewer will find it and it is indefensible · **S3** = real but explicable · **S4** = polish.

| # | Sev | Evidence | Finding | Reference | Effort |
|---|---|---|---|---|---|
| 1 | **S1** | **Observed** | PROXY header trusted from any source; client IP and Guardian IP rules both spoofable | `core/rust/src/main.rs:133`, `:146`, `:172-186` | 4 h |
| 2 | **S1** | **Observed** | `CancelRequest` unhandled and corrupted by the startup rewriter; query cancellation broken | `main.rs:10-12`, `:245-250`, `:299`, `:417-421` | 1 h |
| 3 | **S1** | **Observed** | Rewriter corrupts legitimate SQL containing `application_name` (e.g. `pg_settings` queries, `set_config`) | `main.rs:472-495`, `:516-534` | 2 h (delete) |
| 4 | **S1** | **Observed** | UTF-8 boundary panic in 63-byte truncation; kills the connection with a bare RST | `main.rs:99` (also `:96`) | 3 h |
| 5 | **S1** | **Observed** | Out-of-bounds panic on a 4-byte startup packet, unauthenticated | `main.rs:419`, reached via `:252-256`, `:299` | 1 h |
| 6 | **S1** | **Inspected** | README and architecture guide state opposite TLS behaviour | `README.md:19` vs `PG_PRISM_ARCHITECTURAL_GUIDE.md:30`, `:61` vs `main.rs:116`, `:209-214` | 2 h |
| 7 | **S1** | Predicted | Guardian fully bypassed by ≥1023 bytes of query padding | `main.rs:330` | Doc, 1 h |
| 8 | **S1** | Predicted | `accept()` error propagates out of `main`; `EMFILE` terminates the proxy | `main.rs:146` | 1 h |
| 9 | **S1** | **Inspected** | Build artifacts (706 files, ~95 MB), a 2.5 MB binary, a screenshot, and an **AI chat transcript** committed; history rewrite required | `core/rust/target/**`, `pg-prism-rust`, `Screenshot…jpg`, `Implement PG-Prism Guardian.md`, `pg_prism_test.ipynb` | 2 h |
| 10 | **S1** | **Inspected** | Zero tests, zero CI | repo-wide | 2.5 d |
| 11 | **S1** | **Inspected** | Health check probes Patroni, not the sidecar; a hung sidecar is marked UP. `haproxy.cfg` has no check at all | `README.md:138` vs `haproxy.cfg:16` | 2 h |
| 12 | **S1** | Predicted | Committed notebook shows the proxy faster than a direct connection | `pg_prism_test.ipynb` cells 12, 14 | delete |
| 13 | **S2** | **Observed** | Unbounded allocation from attacker-supplied message length (up to 4 GiB per connection) | `main.rs:195-197`, `:220-221` | 2 h |
| 14 | **S2** | **Observed** | Unbounded, untimed PROXY header read (slowloris + memory growth) | `main.rs:171-172` | 2 h |
| 15 | **S2** | Predicted | IPv6 clients match no `0.0.0.0/0` rule and bypass all Guardian query filtering | `guardian.rs:83-87` | 1 h |
| 16 | **S2** | **Observed** | `RESET application_name;` and dollar-quoted `SET` bypass the interception | `main.rs:466`, `:477` | doc |
| 17 | **S2** | Predicted | Guardian table matching is case-sensitive; `SELECT * FROM SECRETS` bypasses `block_tables: ["secrets"]` | `guardian.rs:161`, `:177` | 1 h |
| 18 | **S2** | Predicted | Guardian config parse failure silently degrades to allow-all | `main.rs:111-114`, `guardian.rs:57-60` | 1 h |
| 19 | **S2** | Predicted | No half-close propagation; task and fd leak per abandoned connection | `main.rs:399` | 3 h |
| 20 | **S2** | **Observed** | No timeouts anywhere: PROXY read, TLS handshake, upstream connect, idle | `main.rs:172`, `:212`, `:291` | 3 h |
| 21 | **S2** | Predicted | Backend unreachable → bare FIN, no `ErrorResponse` | `main.rs:291` | 1 h |
| 22 | **S2** | Predicted | Protocol 3.1/3.2 startup skips Guardian connection checks entirely | `main.rs:12`, `:245`, `:269` | 3 h |
| 23 | **S2** | Predicted | Blocked `Parse` desyncs the extended protocol; `ReadyForQuery` sent mid-sequence | `main.rs:336-345` | 3 h |
| 24 | **S2** | Predicted | Panics in spawned tasks are unlogged and invisible to the client | `main.rs:154-158` | 2 h |
| 25 | **S2** | Predicted | Partial-read error inside blind-forwarding breaks the inner loop only, desyncing the stream | `main.rs:369-375` | 1 h |
| 26 | **S2** | **Inspected** | "Zero allocation / zero dependency / zero overhead" all refuted | `guide:13-15`; `main.rs:189`, `:308`, `:392`; `Cargo.toml` | doc, 2 h |
| 27 | **S2** | Predicted | "Feature parity" false in six observable ways; Python core ignores `LISTEN_HOST`/`LISTEN_PORT` | `guide:15`; `main.py:10-11`, `:262`, `:444`, `:469` | cut the core |
| 28 | **S3** | Predicted | `BufReader::into_inner()` discards buffered bytes at five sites | `main.rs:207`, `:224`, `:228`, `:238`, `:247` | 4 h |
| 29 | **S3** | **Inspected** | No connection limit / no backpressure on accept | `main.rs:145-158` | 2 h |
| 30 | **S3** | Predicted | Overnight `time_range` values never match | `guardian.rs:103-111`, `main.py:172` | 1 h |
| 31 | **S3** | Predicted | `options` parameter never inspected; possible `application_name` override vector | `main.rs:440` | 3 h |
| 32 | **S3** | Predicted | Absent `application_name` yields a leading space (` 1.2.3.4`) in Rust; Python differs | `main.rs:455` vs `main.py:469` | 30 m |
| 33 | **S3** | **Inspected** | PROXY v2 unsupported; `send-proxy-v2` fails at the header check | `main.rs:175` | 1 d |
| 34 | **S3** | **Inspected** | `Dockerfile` never copies `guardian.yaml`; the README quickstart silently runs with no rules | `Dockerfile:1-45`, `README.md:41-56` | 30 m |
| 35 | **S3** | **Inspected** | Runtime shells out to the `openssl` CLI, which the final image may not contain (*unverified*) | `main.rs:33`, `Dockerfile:3`, `:9` | 1 h |
| 36 | **S3** | **Inspected** | Hardcoded PKCS#12 password `"mypassword"` in source | `main.rs:49`, `:63` | 1 h |
| 37 | **S3** | Predicted | `ErrorResponse` omits the required `V` (non-localised severity) field | `main.rs:68-86` | 30 m |
| 38 | **S3** | Predicted | `ReadyForQuery` always claims `I`, misreporting transaction state after a block | `main.rs:341` | 1 h |
| 39 | **S3** | Predicted | Python core's regex YAML parser silently drops block-style lists | `main.py:82-112` | cut the core |
| 40 | **S3** | Predicted | Guardian command matching is substring-based: `DROP` blocks `eavesdropping` | `guardian.rs:152-157` | 3 h |
| 41 | **S3** | **Inspected** | Architecture guide is Turkish, and §8 is addressed to "future AI models" | `PG_PRISM_ARCHITECTURAL_GUIDE.md:297-303` | 1 d |
| 42 | **S3** | **Inspected** | No `SIGTERM` handling or graceful drain | `main.rs:106-160` | 4 h |
| 43 | **S4** | **Inspected** | `benchmark.py` measures `psql` process spawn against a port nothing listens on | `benchmark.py:10-15`, `:24` | delete |
| 44 | **S4** | **Observed** | `bytes` dependency declared and unused | `Cargo.toml:8` | 5 m |
| 45 | **S4** | **Inspected** | Rust badge says 1.80, `Dockerfile` uses 1.85 | `README.md:9` vs `Dockerfile:2` | 5 m |
| 46 | **S4** | **Inspected** | `SSL_ENABLED`, `SSL_CERT_PATH`, `SSL_KEY_PATH` undocumented; the latter two are ignored by the Rust core | `README.md:122-128`, `main.rs:25-27` | 30 m |
| 47 | **S4** | **Inspected** | Dead code: `available_len == 0` branch is unreachable | `main.rs:96-97` | 5 m |
| 48 | **S4** | **Inspected** | `.gitignore` does not exclude generated `*.key`/`*.crt`/`*.p12` | `.gitignore:1-8` | 5 m |
| 49 | **S4** | **Inspected** | `ENV CORE_TYPE=python  ` trailing whitespace before a stray comment line | `Dockerfile:25-26` | 5 m |
| 50 | **S4** | **Inspected** | Hardcoded `POSTGRES_PASSWORD=test123` in the compose file | `docker-compose.yml:11` | 10 m |

**Totals:** 12 × S1, 15 × S2, 16 × S3, 7 × S4. Tier 1 of §13 clears eleven of the twelve S1 findings in about five days; the twelfth (tests and CI) is the two-and-a-half-day Tier 2 item.

---

*Sources consulted for §7: [PgBouncer 1.6 release notes](https://www.pgbouncer.org/2015/08/pgbouncer-1-6), [PgBouncer config reference](https://www.pgbouncer.org/config.html), [pgbouncer#896 on `application_name_add_host`](https://github.com/pgbouncer/pgbouncer/issues/896), [PostgreSQL -hackers: PROXY protocol support](https://www.postgresql.org/message-id/CABUevExJ0ifpUEiX4uOREy0s2kHBrBrb=pXLEHhpMTR1vVR1XA@mail.gmail.com), [Commitfest entry 36/3032](https://commitfest.postgresql.org/36/3032/), [pgcat](https://github.com/postgresml/pgcat). PROXY protocol support in pgcat and Odyssey, and the current commitfest status of the in-core patch, are **unverified** — confirm both before the talk.*

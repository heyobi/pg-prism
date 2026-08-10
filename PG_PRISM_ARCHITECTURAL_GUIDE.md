# PG-Prism: Architecture and Protocol Guide

This document explains how PG-Prism intercepts the PostgreSQL wire protocol, the
design decisions in the Rust core, and the problems that shaped them. It is
written for someone reading the source.

It describes the code as it is, including the parts that are wrong.
[`AUDIT.md`](AUDIT.md) is the record of what is wrong and why; where this guide
touches a known defect it links to the finding number. If the two ever disagree,
`AUDIT.md` is authoritative — it carries evidence and this does not.

---

## 1. What it is

PG-Prism is a per-host sidecar proxy that sits between clients and PostgreSQL,
reads the HAProxy PROXY protocol header, and writes the real client address into
the session's `application_name`. It also carries an optional rule engine
(Guardian) that can refuse connections and block statements.

It is **not** a pooler. It does not multiplex, it does not load balance, and it
holds exactly one backend connection per client connection.

### Design principles

1. **A small, auditable dependency set.** The Rust core uses `tokio`,
   `native-tls`, `serde`/`serde_yaml`, `cidr`, `chrono`, `socket2` and
   `log`/`env_logger`. `native-tls` binds to the platform TLS library — OpenSSL
   on Linux, SChannel on Windows. This is not "zero dependencies"; the goal is a
   set small enough to review in one sitting.

2. **Low latency by not looking.** Messages of 1 KB or more are forwarded without
   being parsed, so bulk traffic pays no inspection cost. A fixed number of
   allocations happens per connection; this is not "zero allocation". See
   `BENCHMARK.md` for measured latency — and note that until a real run fills it
   in, that file has empty tables and no numbers should be quoted from anywhere
   else.

3. **One implementation.** The Rust core is the only maintained one. The original
   Python prototype sits in `contrib/python/` as an unmaintained reference and is
   **not** guaranteed to behave the same way.

### Traffic flow

```text
[Client: DBeaver / application]
       │  (port 5434, TLS)
       ▼
 ┌──────────┐
 │ HAProxy  │  --> mode tcp, adds a PROXY v1 header
 └────┬─────┘
      │  (port 5433, plaintext socket prefixed with the PROXY v1 header)
      ▼
 ┌──────────────┐
 │   PG-Prism   │  --> reads the header, answers SSLRequest,
 │  (sidecar)   │      terminates TLS, evaluates Guardian
 └────┬─────────┘
      │  (port 5432, plaintext TCP, rewritten application_name)
      ▼
 ┌──────────────┐
 │  PostgreSQL  │
 └──────────────┘
```

Two things about this diagram carry the whole security model.

**The backend leg is plaintext.** TLS terminates at PG-Prism, which presents its
own certificate. That hop must not cross a network boundary — it carries
credentials and results in clear — and nothing in the code enforces that. It is
also why `scram-sha-256-plus` is unavailable: channel binding needs one TLS
session, and there are two here.

**The PROXY header is unauthenticated.** It is an assertion by the peer about who
*it* is talking to. Anything that can open a TCP connection to `:5433` can claim
any client address. `TRUSTED_PROXIES` (see §6) is what makes the header
meaningful, and it is the single most important setting in the project.

---

## 2. The PostgreSQL wire protocol, as far as this matters

Protocol 3 is message-based. Every packet after the startup phase begins with a
one-byte **message type** and a four-byte **length**, where the length includes
those four bytes but not the type byte. Startup-phase packets have no type byte.

### 2.1 Startup phase

#### The PROXY v1 header

HAProxy prefixes the connection with a plain-text line:

```text
PROXY TCP4 <client_ip> <haproxy_ip> <client_port> <haproxy_port>\r\n
```

PG-Prism reads to the line terminator and takes the third field. The
specification caps the line at 107 bytes; the reader refuses at 108 rather than
growing a buffer for a client that never sends a newline (finding #14).

IPv6 arrives as `PROXY TCP6 ...` with an IPv6 literal in the same position. The
reader is address-family agnostic — it takes the field as text — and
`tests/proxy_header_forms.rs` confirms both a short literal and a full-length
39-character one survive the parse and the injection.

**PROXY v2 is not supported.** Its header is binary and begins with the signature
`\r\n\r\n\0\r\nQUIT\n`; the v1 reader scans to the first `\n`, which is the second
byte, and rejects the line because it does not start with `PROXY`. The connection
is refused rather than misparsed, which is the right failure, but `send-proxy-v2`
must not be configured.

#### SSLRequest (`80877103`)

A client wanting TLS sends eight bytes first:

- `[00 00 00 08]` — length 8
- `[04 d2 16 2f]` — `80877103`

PG-Prism answers with a single byte: `S` if TLS is enabled, then immediately
starts the handshake; `N` if it is not, and the client decides whether plaintext
is acceptable. A client using `sslmode=require` will refuse, which is correct.

`GSSENCRequest` (`80877104`) is always answered `N`.

#### CancelRequest (`80877102`)

Arrives on a *separate* connection, carries the process ID and secret key of a
different session, and receives no reply at all. There is nothing to inject into
and no user or database for Guardian to evaluate, so PG-Prism relays the payload
byte for byte and closes.

Handling this as a distinct code matters: an earlier version did not recognise
it, so it fell through to the startup rewriter and was corrupted. Query
cancellation did not work through the proxy at all, and nothing reported an error
(finding #2).

#### StartupMessage (`196608` and later)

- `[4 bytes]` total length
- `[4 bytes]` protocol version
- NUL-terminated key/value pairs, terminated by an extra NUL:
  `user\0postgres\0database\0shop\0application_name\0dbeaver\0\0`

**The version is two 16-bit halves,** and this is easy to get wrong. 3.0 is
196608, 3.1 is 196609, 3.2 is 196610. PostgreSQL 18 speaks 3.2, and libpq will
ask for it if a client sets `max_protocol_version`.

Testing `version == 196608` therefore does not mean "is this a startup message",
it means "is this a startup message from an older client". PG-Prism made exactly
that mistake: announcing 3.2 skipped the Guardian connection check *and*, through
a flag that depended on it, every query rule as well — while address injection
kept working, so `pg_stat_activity` looked correctly populated the whole time
(finding #22).

The current code checks the major half only. Any 3.x is accepted and forwarded
with its version untouched, so the server negotiates the minor version with the
client directly. Protocol 2.0 used a different, fixed-width parameter layout that
this proxy cannot parse; it is refused with SQLSTATE `08P01` rather than
forwarded and mangled.

### 2.2 Query phase

**Simple Query (`Q`)** — `b'Q'`, length, then the statement text plus `\0`.

**Extended Query (`P`/`B`/`E`/`S`)** — drivers use this for parameterised
statements. Guardian inspects at the **Parse (`P`)** stage:

- `b'P'`, length
- statement name + `\0` (usually empty)
- statement text + `\0`
- parameter type OIDs

Everything else — Bind, Execute, Sync, COPY data, the entire backend-to-client
direction — is forwarded without inspection.

---

## 3. The Rust core

### 3.1 Dynamic TLS and a boxed stream

Whether a socket is TLS is not known at compile time, so `TcpStream` and
`TlsStream<TcpStream>` have to be handled through one type. A trait alias plus a
boxed trait object does it:

```rust
pub trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

let client_stream: Box<dyn AsyncReadWrite + Unpin + Send>;
```

The cost is one virtual call per read and write. It has not been measured against
the alternative (generic monomorphisation over both stream types), and the
alternative would duplicate the whole connection path.

### 3.2 Splitting the socket, and the borrow checker

Running both directions concurrently means splitting the socket into read and
write halves.

**The problem.** When a query is blocked, the client-to-server task needs to write
an `ErrorResponse` to the client — but the server-to-client task owns the write
half and is using it. Two mutable borrows, one compile error.

**The solution.** Wrap the write half in `Arc<tokio::sync::Mutex<_>>` so both
tasks take the lock:

```rust
let (client_read_half, client_write_half) = tokio::io::split(stream);
let client_write_half = Arc::new(tokio::sync::Mutex::new(client_write_half));
```

This is a real cost: every write to the client takes an async mutex, including
the entire result-set path, where there is no contention to protect against
except during the rare blocked query. It is the price of Guardian being able to
answer a client mid-session.

### 3.3 Ending the connection

The two directions are **not** joined symmetrically, and the asymmetry is
deliberate:

```rust
tokio::select! {
    _ = &mut client_to_server => {
        // Client stopped sending and PostgreSQL has EOF. Wait with no deadline:
        // a long query may still be running and a half-closed client is
        // still reading the results.
        server_to_client.await;
    }
    _ = &mut server_to_client => {
        // PostgreSQL is gone and the client has EOF. Nothing it sends can be
        // answered, so this only bounds a client that ignores the close.
        let _ = timeout(cfg.limits.drain_timeout, client_to_server).await;
    }
}
```

Waiting for both with `try_join!`, which is what the original did, meant a
connection survived until the operating system's TCP timeout whenever one side
went quiet without closing.

That still leaves one case: a client half-closes, and the backend then becomes
*unreachable* without closing — a firewall dropping the flow, a middlebox losing
state. The read blocks forever and, with keepalive off by default, the kernel
never gives up either. TCP keepalive is the answer, not a general idle timeout: an
application legitimately holds a connection idle for hours, and keepalive
distinguishes idle from unreachable. An idle-but-alive peer answers the probe.

It deliberately does not help with a peer that is reachable but hung — the kernel
answers probes even when the process is stuck, and that is indistinguishable from
a slow query.

**This is not tested end to end.** Proving it needs a firewall that drops packets
without sending RST, which CI cannot do. The test asserts the socket option is
set, which covers the code path and not the kernel behaviour.

---

## 4. Two algorithms worth explaining

### 4.1 Truncating `application_name`

PostgreSQL's `NAMEDATALEN` limit is 63 **bytes**. Given a name of `DBeaver` and an
address of `192.168.1.50`, the new value is `DBeaver - 192.168.1.50`. If the
original name is long, something has to be cut — and it must not be the address,
because the address is the entire point.

The obvious implementation is wrong twice.

**First**, `&str[..n]` is a byte index, and slicing a multi-byte character in half
panics. Since this runs on an unauthenticated startup packet, that is a remote
crash (finding #4).

**Second, and much less obvious:** `application_name` is ASCII-only, and
PostgreSQL runs the value through `pg_clean_ascii()`, which since version 14
replaces every non-printable-ASCII byte with a four-character `\xNN` escape —
*and only then* applies `NAMEDATALEN`. A two-byte `ç` does not cost two of the
sixty-three characters. It costs eight.

So budgeting in raw bytes overflows on the server, and the server truncates from
the end, which is where the address is. A client with a Turkish application name
got a session with no address in it and no error anywhere (finding #52). This was
invisible to the fake-backend test suite, which stores whatever it is handed; it
surfaced on the first run against a real server.

The fix budgets in *stored* length:

```rust
fn stored_len(byte: u8) -> usize {
    if (0x20..0x7f).contains(&byte) { 1 } else { 4 }
}
```

and truncates on character boundaries until the stored cost fits the remaining
budget. The suffix is reserved first, so the address always survives.

### 4.2 Blocking a query without dropping the connection

When Guardian blocks a statement, closing the socket would be both unhelpful and
a lie about what happened. Instead PG-Prism behaves like the database and returns
an error.

An `ErrorResponse` is type `E`, then field identifiers with NUL-terminated
strings, then a final NUL:

```rust
body.push(b'S'); body.extend_from_slice(b"ERROR\0");  // severity, localised
body.push(b'V'); body.extend_from_slice(b"ERROR\0");  // severity, non-localised
body.push(b'C'); /* SQLSTATE */                       // e.g. 42501
body.push(b'M'); /* message */
body.push(0);                                          // terminator
```

The `V` field is required since protocol 3.0 and is always sent by a real server.
It was missing here, and how a given driver reacts to its absence was never
established (finding #37).

After the error, the client's state machine needs to be told the server is ready
again, or it waits forever:

```rust
// Z + [00 00 00 05] + I (transaction status: idle)
let ready_for_query = b"Z\x00\x00\x00\x05I";
```

**The status byte is always `I`.** If the client was inside a transaction it
should be `T`, or `E` if the transaction had already failed. Telling a client in
a transaction that it is idle is a lie the client may act on (finding #38).

There is a second problem with blocking at `P`: the client is mid-sequence in the
extended protocol, and the Bind and Execute that follow are still forwarded to a
backend that never saw the Parse (finding #23). Neither is fixed.

---

## 5. Guardian

Rules live in `guardian.yaml` and are scanned top to bottom, **first match wins**.

```yaml
rules:
  # Analysts may connect, but not touch the sensitive tables.
  - name: "Analyst_Read_Only"
    action: "INSPECT"
    users: ["analyst"]
    block_queries: ["DROP", "TRUNCATE", "DELETE"]
    block_tables: ["secrets", "billing_info"]

  # Batch jobs run overnight only.
  - name: "Batch_Window"
    action: "ALLOW"
    users: ["batch"]
    time_range: "22:00-06:00"
```

Notes that are not obvious from the shape:

- **`ALLOW` means "skip all query inspection".** It is a bypass, not a
  permission. A rule granting `ALLOW` to a superuser on loopback will also
  silently exempt anything else matching it — including a demo you meant to
  block.
- **Omitting `ips` is how you say "any address".** `0.0.0.0/0` is the IPv4
  default route and does not match an IPv6 client, so a rule written that way
  stops applying the moment somebody connects over IPv6 (finding #15). The loader
  warns about single-family rules at startup.
- **`time_range` wraps midnight.** `22:00-06:00` works. An earlier version
  compared the strings directly, so it required a time both after 22:00 and
  before 06:00 and matched nothing (finding #30).
- **Matching is whole-token and ASCII-case-insensitive.** `DROP` no longer
  matches `eavesdropping`, and `secrets` does match `SECRETS`. It still matches
  inside comments and string literals, because this searches text and does not
  parse SQL.

### What Guardian is not

It inspects `Q` and `P` messages **under 1 KB**. Padding a statement past that
bypasses every rule (finding #7). It is a guard rail against a mistake, not a
control against an adversary. Authorisation belongs to PostgreSQL, which is the
only component here that knows what a table is.

Several ways a ruleset can be silently inert are catalogued in `AUDIT.md` §14 —
a misspelled field, one bad CIDR, a malformed time range. None is fixed.

---

## 6. Configuration and deployment

`TRUSTED_PROXIES` is a comma-separated list of CIDRs or bare addresses permitted
to send a PROXY header, defaulting to loopback. A malformed list is a startup
failure. This deliberately mirrors the `proxy_servers` GUC in the in-core PROXY
protocol patch, down to the name and the fail-closed behaviour.

The full environment variable table is in the [README](README.md#configuration).
Local setup, including a Docker-free path, is in
[`docs/DEV_ENVIRONMENT.md`](docs/DEV_ENVIRONMENT.md).

### HAProxy

```text
frontend postgres_in
    bind *:5434
    mode tcp
    default_backend pg_prism_backend

backend pg_prism_backend
    mode tcp
    server pg_prism pg-prism:5433 send-proxy
```

`send-proxy` is v1. `send-proxy-v2` will not work: PG-Prism only parses v1, and
the v2 binary header does not begin with `PROXY`, so the connection is refused as
malformed.

### Health checking

PG-Prism exposes no health endpoint. The deployment example checks Patroni's REST
API, which reports on **PostgreSQL**, so a hung sidecar in front of a healthy
database is still marked UP and still receives traffic. A TCP check against
`:5433` is the minimum improvement and is still not a liveness check
(`AUDIT.md` §8).

---

## 7. Testing

Two suites, and the split is the point.

`cargo test` runs the hermetic ones: pure protocol functions plus an in-process
fake backend that records what it was sent. Fast, no server, runs anywhere.

`cargo test -- --include-ignored` adds a suite that drives a **real PostgreSQL**
through `tokio-postgres`. CI runs it against 16 and 18 on every push.

The second suite exists because a fake backend agrees with you about what is worth
recognising. It stores whatever `application_name` it is handed, so it could
never have shown finding #52; it does not negotiate protocol versions, so it did
not prompt anyone to look at #22. Both were found by putting a real server at the
other end.

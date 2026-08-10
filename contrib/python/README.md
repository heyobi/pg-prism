# Python core — unmaintained reference implementation

**This is not the product. Do not deploy it.**

`main.py` was the original prototype of PG-Prism. It is kept here because it is
short enough to read in one sitting and it documents the idea — read the PROXY
header, rewrite `application_name` in the StartupMessage, forward everything else —
without the error handling and bounds checking that the real implementation needs.

The maintained implementation is the Rust core in [`core/rust/`](../../core/rust/).

## Why it was retired

It was previously presented as a second, interchangeable core with "feature parity"
with the Rust implementation. That claim was false. The two diverged in at least
six externally visible ways:

| Behaviour | Rust core | Python core |
| :--- | :--- | :--- |
| `LISTEN_HOST` / `LISTEN_PORT` | Honoured | **Hardcoded and ignored** (`main.py:10-11`) |
| `application_name` absent from StartupMessage | Appends `" - <ip>"` | Appends the bare IP |
| Non-ASCII `application_name` at the 63-byte limit | Truncates on a byte boundary | Truncates on a code point, can exceed 63 bytes |
| Startup parameter order | Preserved | Rebuilt from a `dict`, reordered |
| Duplicate startup parameter keys | All kept | Silently deduplicated |
| Blocked query | Connection stays open | Connection is torn down |

It also parses `guardian.yaml` with a hand-rolled regex parser (`main.py:82-112`)
that only understands inline lists (`key: [a, b]`). Any block-style list is
silently dropped, which quietly weakens the rules rather than failing.

Maintaining two implementations of a wire protocol to the standard this project
needs was not achievable, so the Python core was retired rather than left in place
implying a guarantee it did not meet.

## If you want to run it anyway

It is standard library only, no dependencies:

```bash
PG_HOST=127.0.0.1 PG_PORT=5432 python3 main.py
```

It listens on `0.0.0.0:5433` and that is not configurable without editing the
source. It has no tests, and none of the fixes made to the Rust core — the trusted
proxy allowlist, the input bounds, the panic fixes, the `CancelRequest`
pass-through — have been applied here.

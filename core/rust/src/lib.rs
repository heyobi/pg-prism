//! PG-Prism: a sidecar proxy that consumes the HAProxy PROXY protocol header and
//! injects the originating client address into PostgreSQL's `application_name`.
//!
//! The crate is split into a library and a thin binary so that the protocol
//! handling can be exercised by unit and integration tests. A binary-only crate
//! cannot be imported from `tests/`.

pub mod guardian;
pub mod protocol;
pub mod proxy;
pub mod tls;

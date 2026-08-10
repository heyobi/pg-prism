//! End-to-end tests against a real PostgreSQL server.
//!
//! The fake backend in `tests/common` is fast and deterministic, but it is a
//! backend we wrote, so it agrees with our own protocol assumptions by
//! construction — and those assumptions are what produced the bugs in AUDIT.md.
//! These tests use `tokio_postgres`, an independently written driver, against a
//! real server, so both ends of the conversation are somebody else's code.
//!
//! # Why these are `#[ignore]`
//!
//! They need a PostgreSQL server, which not every developer machine has. They
//! are **not** optional: `.github/workflows/ci.yml` runs them with
//! `--include-ignored` against a `postgres` service container on every push. A
//! test suite that exists but never runs is worse than none, because it
//! manufactures confidence.
//!
//! Run locally with:
//!
//! ```text
//! PGHOST=127.0.0.1 PGPORT=5432 PGUSER=postgres PGPASSWORD=secret \
//!   cargo test --test real_postgres -- --include-ignored --test-threads=1
//! ```
//!
//! The client reaches PostgreSQL through an in-process PG-Prism, prefixing each
//! connection with a PROXY header, exactly as HAProxy would.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_postgres::config::SslMode;
use tokio_postgres::{Client, Config, NoTls};

use pg_prism_rust::limits::Limits;
use pg_prism_rust::proxy::ProxyConfig;

/// The address the forged PROXY header claims. A documentation-range address,
/// so it can never collide with anything real in CI.
const FORGED_CLIENT_IP: &str = "203.0.113.99";

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn upstream() -> String {
    format!(
        "{}:{}",
        env_or("PGHOST", "127.0.0.1"),
        env_or("PGPORT", "5432")
    )
}

fn pg_config(application_name: &str) -> Config {
    let mut cfg = Config::new();
    cfg.user(env_or("PGUSER", "postgres"))
        .password(env_or("PGPASSWORD", "postgres"))
        .dbname(env_or("PGDATABASE", "postgres"))
        .application_name(application_name);
    cfg
}

async fn start_proxy(tls: bool) -> SocketAddr {
    let tls_acceptor = if tls {
        Some(Arc::new(
            pg_prism_rust::tls::load_tls_acceptor().expect("could not build a TLS acceptor"),
        ))
    } else {
        None
    };

    spawn_proxy_serving(ProxyConfig {
        pg_addr: upstream(),
        guardian: allow_all_guardian(),
        tls_acceptor,
        trusted: trust_loopback(),
        limits: Limits::default(),
    })
    .await
}

/// Opens a TCP connection to the proxy and writes the PROXY header, leaving the
/// stream positioned exactly where a driver expects to start.
async fn proxied_stream(proxy_addr: SocketAddr) -> TcpStream {
    let mut sock = TcpStream::connect(proxy_addr)
        .await
        .expect("connect to proxy");
    sock.write_all(&proxy_v1_header(FORGED_CLIENT_IP, 40001))
        .await
        .expect("write PROXY header");
    sock.flush().await.expect("flush PROXY header");
    sock
}

/// Connects a real driver through the proxy over plaintext.
async fn connect_plain(proxy_addr: SocketAddr, application_name: &str) -> Client {
    let stream = proxied_stream(proxy_addr).await;
    let (client, connection) = pg_config(application_name)
        .connect_raw(stream, NoTls)
        .await
        .expect("driver handshake through the proxy failed");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
}

async fn own_application_name(client: &Client) -> String {
    client
        .query_one(
            "SELECT application_name FROM pg_stat_activity WHERE pid = pg_backend_pid()",
            &[],
        )
        .await
        .expect("query pg_stat_activity")
        .get(0)
}

// ---------------------------------------------------------------------------
// 1. The smallest end-to-end proof: does the whole point of the project work?
// ---------------------------------------------------------------------------

/// A client connects through the proxy carrying a PROXY header, and the address
/// from that header is what PostgreSQL reports in pg_stat_activity.
///
/// This is the claim the talk is built on. Everything else is detail.
#[tokio::test]
#[ignore = "needs a PostgreSQL server; CI runs this with --include-ignored"]
async fn forged_client_ip_reaches_pg_stat_activity() {
    let proxy = start_proxy(false).await;
    let client = connect_plain(proxy, "invoicing-worker").await;

    let seen = own_application_name(&client).await;
    assert_eq!(
        seen,
        format!("invoicing-worker - {}", FORGED_CLIENT_IP),
        "the client address from the PROXY header did not reach pg_stat_activity"
    );
}

/// PostgreSQL still sees the proxy as the peer. Spelling this out because it is
/// the limitation that motivates the whole application_name workaround: the
/// real fix is client_addr, which needs the in-core PROXY protocol patch.
#[tokio::test]
#[ignore = "needs a PostgreSQL server; CI runs this with --include-ignored"]
async fn client_addr_still_shows_the_proxy_not_the_real_client() {
    let proxy = start_proxy(false).await;
    let client = connect_plain(proxy, "topology-check").await;

    let addr: Option<std::net::IpAddr> = client
        .query_one(
            "SELECT client_addr FROM pg_stat_activity WHERE pid = pg_backend_pid()",
            &[],
        )
        .await
        .expect("query client_addr")
        .get(0);

    assert_ne!(
        addr.map(|a| a.to_string()).as_deref(),
        Some(FORGED_CLIENT_IP),
        "client_addr unexpectedly carried the real client address"
    );
}

/// A connection with no application_name at all still gets one.
#[tokio::test]
#[ignore = "needs a PostgreSQL server; CI runs this with --include-ignored"]
async fn absent_application_name_is_added() {
    let proxy = start_proxy(false).await;

    let stream = proxied_stream(proxy).await;
    let mut cfg = Config::new();
    cfg.user(env_or("PGUSER", "postgres"))
        .password(env_or("PGPASSWORD", "postgres"))
        .dbname(env_or("PGDATABASE", "postgres"));
    let (client, connection) = cfg
        .connect_raw(stream, NoTls)
        .await
        .expect("handshake without application_name");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let seen = own_application_name(&client).await;
    assert!(
        seen.contains(FORGED_CLIENT_IP),
        "expected the client address in application_name, got {:?}",
        seen
    );
}

/// A multi-byte application_name at the length limit. This is the path that
/// panicked before A3; here it is proven end to end, including that PostgreSQL
/// accepts the truncated value rather than rejecting the startup packet.
#[tokio::test]
#[ignore = "needs a PostgreSQL server; CI runs this with --include-ignored"]
async fn multibyte_application_name_survives_truncation() {
    let proxy = start_proxy(false).await;
    let long_name = "çalışan".repeat(12); // well past 63 bytes, 2-byte characters
    let client = connect_plain(proxy, &long_name).await;

    let seen = own_application_name(&client).await;
    assert!(
        seen.len() <= 63,
        "PostgreSQL reported {} bytes, over NAMEDATALEN",
        seen.len()
    );
    assert!(
        seen.ends_with(FORGED_CLIENT_IP),
        "the address was truncated away: {:?}",
        seen
    );
}

// ---------------------------------------------------------------------------
// 2. TLS
// ---------------------------------------------------------------------------

/// sslmode=require through the proxy's own certificate.
///
/// `danger_accept_invalid_certs` is not laziness: it is what sslmode=require
/// means. The mode encrypts without authenticating, which is exactly why
/// verify-full cannot work against a self-signed certificate the proxy mints
/// for itself. The next test pins that down.
#[tokio::test]
#[ignore = "needs a PostgreSQL server; CI runs this with --include-ignored"]
async fn sslmode_require_completes_through_tls_termination() {
    use postgres_native_tls::MakeTlsConnector;
    use tokio_postgres::tls::MakeTlsConnect;

    let proxy = start_proxy(true).await;
    let stream = proxied_stream(proxy).await;

    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .unwrap();
    let mut maker = MakeTlsConnector::new(connector);
    let tls = MakeTlsConnect::<TcpStream>::make_tls_connect(&mut maker, "localhost").unwrap();

    let mut cfg = pg_config("tls-client");
    cfg.ssl_mode(SslMode::Require);
    let (client, connection) = cfg
        .connect_raw(stream, tls)
        .await
        .expect("sslmode=require handshake through the proxy failed");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let seen = own_application_name(&client).await;
    assert_eq!(seen, format!("tls-client - {}", FORGED_CLIENT_IP));
}

/// Certificate verification fails against the self-signed certificate, which is
/// what a `verify-full` client experiences. Asserting the failure keeps the
/// README honest: this is a documented limitation, not an untested claim.
#[tokio::test]
#[ignore = "needs a PostgreSQL server; CI runs this with --include-ignored"]
async fn verifying_clients_reject_the_self_signed_certificate() {
    use postgres_native_tls::MakeTlsConnector;
    use tokio_postgres::tls::MakeTlsConnect;

    let proxy = start_proxy(true).await;
    let stream = proxied_stream(proxy).await;

    // A verifying connector: the default, with no danger_* escape hatches.
    let connector = native_tls::TlsConnector::builder().build().unwrap();
    let mut maker = MakeTlsConnector::new(connector);
    let tls = MakeTlsConnect::<TcpStream>::make_tls_connect(&mut maker, "localhost").unwrap();

    let mut cfg = pg_config("verify-full-client");
    cfg.ssl_mode(SslMode::Require);
    let result = cfg.connect_raw(stream, tls).await;

    assert!(
        result.is_err(),
        "a verifying client accepted the proxy's self-signed certificate"
    );
}

// ---------------------------------------------------------------------------
// 3. SCRAM
// ---------------------------------------------------------------------------

/// The proxy relays the SCRAM exchange untouched.
///
/// The CI server is configured with scram-sha-256, so every test in this file
/// authenticates that way; this one asserts it explicitly rather than relying on
/// it as a side effect, and fails loudly if the server was set to trust.
#[tokio::test]
#[ignore = "needs a PostgreSQL server; CI runs this with --include-ignored"]
async fn scram_authentication_succeeds_through_the_proxy() {
    let proxy = start_proxy(false).await;
    let client = connect_plain(proxy, "scram-client").await;

    let method: String = client
        .query_one(
            "SELECT COALESCE((SELECT substring(rolpassword from 1 for 14)
                              FROM pg_authid WHERE rolname = current_user), 'none')",
            &[],
        )
        .await
        .expect("read pg_authid")
        .get(0);

    assert_eq!(
        method, "SCRAM-SHA-256$",
        "expected the CI server to require scram-sha-256, got {:?}. \
         If this is 'none' the server is using trust auth and the SCRAM path \
         is not actually being exercised.",
        method
    );
}

/// A wrong password must still be rejected. Proves the proxy is relaying the
/// exchange rather than short-circuiting it.
#[tokio::test]
#[ignore = "needs a PostgreSQL server; CI runs this with --include-ignored"]
async fn scram_rejects_a_wrong_password() {
    let proxy = start_proxy(false).await;
    let stream = proxied_stream(proxy).await;

    let mut cfg = pg_config("scram-bad-password");
    cfg.password("definitely-not-the-password");
    let result = cfg.connect_raw(stream, NoTls).await;

    assert!(result.is_err(), "a wrong password was accepted");
}

// ---------------------------------------------------------------------------
// 4. Cancellation
// ---------------------------------------------------------------------------

/// AUDIT.md finding #2. CancelRequest opens a *second* connection carrying a
/// different startup packet. The proxy did not recognise the code and fed the
/// 16-byte request through the application_name rewriter, corrupting it, so
/// cancellation silently did nothing.
///
/// Expected to fail until A4.
#[tokio::test]
#[ignore = "needs a PostgreSQL server; CI runs this with --include-ignored"]
async fn cancel_request_stops_a_running_query() {
    let proxy = start_proxy(false).await;
    let client = connect_plain(proxy, "cancel-client").await;
    let cancel_token = client.cancel_token();

    let query = tokio::spawn(async move { client.query_one("SELECT pg_sleep(30)", &[]).await });

    // Let the query actually start before cancelling it.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let cancel_stream = proxied_stream(proxy).await;
    cancel_token
        .cancel_query_raw(cancel_stream, NoTls)
        .await
        .expect("sending the CancelRequest through the proxy failed");

    let outcome = tokio::time::timeout(Duration::from_secs(10), query)
        .await
        .expect("the query was never cancelled: it outlived the timeout")
        .expect("query task panicked");

    let err = outcome.expect_err("pg_sleep(30) returned successfully, so it was not cancelled");
    assert_eq!(
        err.code(),
        Some(&tokio_postgres::error::SqlState::QUERY_CANCELED),
        "expected SQLSTATE 57014 query_canceled, got {:?}",
        err
    );
}

//! AUDIT.md finding #3: the post-handshake `SET application_name` rewriter
//! matched the literal text `application_name` anywhere in a statement and then
//! rewrote whatever sat between the next two single quotes. That corrupts
//! ordinary SQL that merely mentions the setting.
//!
//! The proxy does not parse SQL, so statements must reach PostgreSQL byte for
//! byte. These tests hold that line.

mod common;

use std::time::Duration;

use common::*;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

const WAIT: Duration = Duration::from_secs(5);

/// Opens a session through the proxy and returns the client socket, having
/// waited for the startup message to reach the backend.
async fn open_session(backend: &mut FakeBackend, proxy_addr: std::net::SocketAddr) -> TcpStream {
    let mut wire = proxy_v1_header("203.0.113.99", 40001);
    wire.extend_from_slice(&startup_message(&[
        ("user", "postgres"),
        ("database", "postgres"),
        ("application_name", "app"),
    ]));
    let sock = connect_and_send(proxy_addr, &wire).await.unwrap();

    // Drain the startup capture so later assertions look at query frames.
    let captured = std::mem::replace(&mut backend.captured, tokio::sync::oneshot::channel().1);
    with_timeout(WAIT, captured)
        .await
        .expect("startup never reached the backend")
        .expect("capture dropped");

    sock
}

/// Frames a Simple Query message.
fn query(sql: &str) -> Vec<u8> {
    let mut payload = sql.as_bytes().to_vec();
    payload.push(0);
    let mut msg = vec![b'Q'];
    msg.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
    msg.extend_from_slice(&payload);
    msg
}

async fn round_trip(sql: &str) -> Frame {
    let mut backend = spawn_fake_backend().await;
    let proxy = spawn_proxy_once(backend.addr, allow_all_guardian()).await;
    let mut sock = open_session(&mut backend, proxy).await;

    sock.write_all(&query(sql)).await.unwrap();
    sock.flush().await.unwrap();

    backend
        .next_frame(WAIT)
        .await
        .expect("the query never reached the backend")
}

/// The headline corruption. The first single quote after the literal text
/// `application_name` is that literal's own closing quote, so the rewriter
/// swallowed the rest of the predicate.
///
/// Observed before the fix, PostgreSQL received:
///   SELECT * FROM pg_settings WHERE name = 'application_name' AND setting =  - 203.0.113.99'x'
#[tokio::test]
async fn a_query_mentioning_application_name_is_not_rewritten() {
    let sql = "SELECT * FROM pg_settings WHERE name = 'application_name' AND setting = 'x'";
    let frame = round_trip(sql).await;
    assert_eq!(frame.msg_type, b'Q');
    assert_eq!(frame.text(), sql, "the proxy modified a legitimate query");
}

/// set_config() has the setting name as a quoted argument, so the rewriter
/// mangled the argument list into a syntax error.
#[tokio::test]
async fn set_config_call_is_not_rewritten() {
    let sql = "SELECT set_config('application_name', 'reporting', false)";
    let frame = round_trip(sql).await;
    assert_eq!(frame.text(), sql, "the proxy modified a set_config call");
}

/// A statement that merely stores the word in a table.
#[tokio::test]
async fn string_literals_mentioning_the_setting_are_not_rewritten() {
    let sql = "INSERT INTO audit_log (note) VALUES ('changed application_name to ''x''')";
    let frame = round_trip(sql).await;
    assert_eq!(frame.text(), sql, "the proxy modified a string literal");
}

/// The proxy no longer intercepts SET at all, so the client's value reaches
/// PostgreSQL unchanged and wins.
///
/// This is the honest behaviour, and it is documented rather than papered over:
/// application_name is an observability aid, not an audit control. The previous
/// interception was bypassable with RESET, with dollar quoting, and with a
/// kilobyte of padding, so it bought nothing while corrupting valid SQL.
#[tokio::test]
async fn a_client_set_reaches_postgres_unchanged() {
    let sql = "SET application_name = 'whatever-the-client-wants'";
    let frame = round_trip(sql).await;
    assert_eq!(frame.text(), sql);
}

/// RESET was always forwarded untouched, because the rewriter needed two single
/// quotes to act on. Kept as a test so the limitation stays visible.
#[tokio::test]
async fn reset_application_name_reaches_postgres_unchanged() {
    let sql = "RESET application_name";
    let frame = round_trip(sql).await;
    assert_eq!(frame.text(), sql);
}

/// Extended-protocol Parse messages are forwarded intact, including the
/// parameter-type tail after the query string.
#[tokio::test]
async fn parse_messages_are_forwarded_intact() {
    let mut backend = spawn_fake_backend().await;
    let proxy = spawn_proxy_once(backend.addr, allow_all_guardian()).await;
    let mut sock = open_session(&mut backend, proxy).await;

    // Parse: statement name, query, then a two-byte parameter count.
    let mut payload = Vec::new();
    payload.extend_from_slice(b"stmt1\0");
    payload.extend_from_slice(b"SET application_name = 'from-jdbc'\0");
    payload.extend_from_slice(&1u16.to_be_bytes());
    payload.extend_from_slice(&25u32.to_be_bytes()); // oid for text

    let mut msg = vec![b'P'];
    msg.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
    msg.extend_from_slice(&payload);

    sock.write_all(&msg).await.unwrap();
    sock.flush().await.unwrap();

    let frame = backend
        .next_frame(WAIT)
        .await
        .expect("the Parse never reached the backend");
    assert_eq!(frame.msg_type, b'P');
    assert_eq!(frame.payload, payload, "the proxy modified a Parse message");
}

/// A query large enough to skip the sub-1 KB inspection path must arrive
/// intact too. This is the blind-forwarding branch.
#[tokio::test]
async fn large_queries_are_forwarded_intact() {
    let sql = format!("SELECT 1 -- {}", "x".repeat(2000));
    let frame = round_trip(&sql).await;
    assert_eq!(frame.text(), sql);
}

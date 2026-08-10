//! AUDIT.md finding #22: the proxy recognises exactly one startup code,
//! 196608, which is protocol 3.0. PostgreSQL 18 speaks 3.2, and libpq can be
//! asked for it with `max_protocol_version`.
//!
//! Same failure class as #52: if the code is not recognised, something silently
//! does not happen and the result still looks plausible.
//!
//! These tests are written before any fix, to establish what actually happens.

mod common;

use std::time::Duration;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const WAIT: Duration = Duration::from_secs(5);

const PROTO_3_0: u32 = 196608;
const PROTO_3_1: u32 = 196609;
const PROTO_3_2: u32 = 196610;

/// A StartupMessage announcing an arbitrary protocol version.
fn startup_with_version(version: u32, params: &[(&str, &str)]) -> Vec<u8> {
    let mut payload = version.to_be_bytes().to_vec();
    for (k, v) in params {
        payload.extend_from_slice(k.as_bytes());
        payload.push(0);
        payload.extend_from_slice(v.as_bytes());
        payload.push(0);
    }
    payload.push(0);

    let mut msg = ((payload.len() + 4) as u32).to_be_bytes().to_vec();
    msg.extend_from_slice(&payload);
    msg
}

fn session_params() -> Vec<(&'static str, &'static str)> {
    vec![
        ("user", "app_user"),
        ("database", "shop"),
        ("application_name", "modern-driver"),
    ]
}

/// Baseline. On 3.0 a DENY rule denies the connection: the client is told, and
/// the backend is never contacted.
#[tokio::test]
async fn protocol_3_0_is_subject_to_guardian_connection_rules() {
    let backend = spawn_fake_backend().await;
    let proxy = spawn_proxy_once(backend.addr, deny_all_guardian()).await;

    let mut wire = proxy_v1_header("203.0.113.99", 40001);
    wire.extend_from_slice(&startup_with_version(PROTO_3_0, &session_params()));
    let mut sock = connect_and_send(proxy, &wire).await.unwrap();

    let mut buf = vec![0u8; 256];
    let n = with_timeout(WAIT, sock.read(&mut buf))
        .await
        .expect("no answer")
        .expect("read failed");
    assert_eq!(buf[0], b'E', "expected an ErrorResponse");
    assert!(
        String::from_utf8_lossy(&buf[5..n]).contains("28000"),
        "expected SQLSTATE 28000"
    );

    let reached = with_timeout(Duration::from_millis(300), backend.captured).await;
    assert!(reached.is_none(), "a denied connection reached the backend");
}

/// **Finding #22.** The same connection, announcing 3.2 instead of 3.0. If
/// Guardian is skipped, a DENY rule stops denying and the client is through.
#[tokio::test]
async fn protocol_3_2_is_subject_to_guardian_connection_rules() {
    let backend = spawn_fake_backend().await;
    let proxy = spawn_proxy_once(backend.addr, deny_all_guardian()).await;

    let mut wire = proxy_v1_header("203.0.113.99", 40001);
    wire.extend_from_slice(&startup_with_version(PROTO_3_2, &session_params()));
    let _sock = connect_and_send(proxy, &wire).await.unwrap();

    let reached = with_timeout(Duration::from_millis(500), backend.captured).await;
    assert!(
        reached.is_none(),
        "a DENY rule did not apply to a protocol 3.2 connection: announcing a \
         newer protocol version bypasses Guardian entirely"
    );
}

/// 3.1 too, for completeness: any minor above 0 takes the same path.
#[tokio::test]
async fn protocol_3_1_is_subject_to_guardian_connection_rules() {
    let backend = spawn_fake_backend().await;
    let proxy = spawn_proxy_once(backend.addr, deny_all_guardian()).await;

    let mut wire = proxy_v1_header("203.0.113.99", 40001);
    wire.extend_from_slice(&startup_with_version(PROTO_3_1, &session_params()));
    let _sock = connect_and_send(proxy, &wire).await.unwrap();

    let reached = with_timeout(Duration::from_millis(500), backend.captured).await;
    assert!(
        reached.is_none(),
        "a DENY rule did not apply to a protocol 3.1 connection"
    );
}

/// Query-level rules depend on the same flag. If the connection check was
/// skipped, `context_initialized` stays false and blocked statements are
/// forwarded.
#[tokio::test]
async fn protocol_3_2_is_subject_to_guardian_query_rules() {
    use pg_prism_rust::guardian::{Action, Guardian, Rule};
    use std::sync::Arc;

    let guardian = Arc::new(Guardian {
        rules: vec![Rule {
            name: "block-drops".to_string(),
            action: Action::INSPECT,
            ips: None,
            users: None,
            databases: None,
            time_range: None,
            block_queries: Some(vec!["DROP".to_string()]),
            block_tables: None,
        }],
    });

    let mut backend = spawn_fake_backend().await;
    let proxy = spawn_proxy_once(backend.addr, guardian).await;

    let mut wire = proxy_v1_header("203.0.113.99", 40001);
    wire.extend_from_slice(&startup_with_version(PROTO_3_2, &session_params()));
    let mut sock = connect_and_send(proxy, &wire).await.unwrap();

    let captured = std::mem::replace(&mut backend.captured, tokio::sync::oneshot::channel().1);
    with_timeout(WAIT, captured)
        .await
        .expect("startup never arrived")
        .expect("capture dropped");

    let sql = "DROP TABLE secrets";
    let mut payload = sql.as_bytes().to_vec();
    payload.push(0);
    let mut msg = vec![b'Q'];
    msg.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
    msg.extend_from_slice(&payload);
    sock.write_all(&msg).await.unwrap();
    sock.flush().await.unwrap();

    let frame = backend.next_frame(Duration::from_secs(2)).await;
    assert!(
        frame.is_none(),
        "a blocked statement reached the backend on a protocol 3.2 connection: \
         query inspection is skipped whenever the startup code is not exactly \
         196608"
    );
}

/// Whatever happens to Guardian, the address injection must still work: an
/// unrecognised version must not mean an unattributed connection.
#[tokio::test]
async fn protocol_3_2_still_gets_the_client_address_injected() {
    let backend = spawn_fake_backend().await;
    let proxy = spawn_proxy_once(backend.addr, allow_all_guardian()).await;

    let mut wire = proxy_v1_header("203.0.113.99", 40001);
    wire.extend_from_slice(&startup_with_version(PROTO_3_2, &session_params()));
    let _sock = connect_and_send(proxy, &wire).await.unwrap();

    let capture = with_timeout(WAIT, backend.captured)
        .await
        .expect("startup never arrived")
        .expect("capture dropped");

    assert_eq!(
        capture.protocol_version(),
        Some(PROTO_3_2),
        "the proxy must forward the version the client asked for, unchanged"
    );
    assert_eq!(
        capture.param("application_name").as_deref(),
        Some("modern-driver - 203.0.113.99")
    );
}

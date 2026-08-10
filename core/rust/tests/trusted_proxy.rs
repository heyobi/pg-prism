//! AUDIT.md finding #1: the PROXY header was accepted from any peer, so anyone
//! who could reach the listener could assert an arbitrary client address, both
//! falsifying pg_stat_activity and defeating Guardian's `ips:` rules.

mod common;

use std::time::Duration;

use common::*;
use tokio::io::AsyncReadExt;

fn forged_connection_bytes() -> Vec<u8> {
    let mut wire = proxy_v1_header("203.0.113.99", 12345);
    wire.extend_from_slice(&startup_message(&[
        ("user", "postgres"),
        ("database", "postgres"),
        ("application_name", "psql"),
    ]));
    wire
}

/// The fix. A peer that is not in TRUSTED_PROXIES has its connection dropped
/// before the header is parsed, so nothing reaches the backend at all.
#[tokio::test]
async fn untrusted_peer_is_refused_and_never_reaches_the_backend() {
    let backend = spawn_fake_backend().await;
    let proxy_addr =
        spawn_proxy_once_with_trust(backend.addr, allow_all_guardian(), trust_nobody_local()).await;

    let mut sock = connect_and_send(proxy_addr, &forged_connection_bytes())
        .await
        .unwrap();

    // The proxy closes without replying. Because it refuses *before* reading,
    // the unread request bytes sit in the receive buffer, so the kernel answers
    // the close with RST rather than a clean FIN. Either is a refusal; what
    // matters is that no protocol bytes come back.
    let mut buf = [0u8; 64];
    match with_timeout(Duration::from_secs(5), sock.read(&mut buf))
        .await
        .expect("proxy did not close the connection")
    {
        Ok(0) => {}
        Ok(n) => panic!("proxy sent {} bytes to an untrusted peer: {:?}", n, &buf[..n]),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(e) => panic!("unexpected error: {e}"),
    }

    // And the backend was never contacted.
    let reached_backend = with_timeout(Duration::from_millis(500), backend.captured).await;
    assert!(
        reached_backend.is_none(),
        "an untrusted peer reached the backend"
    );
}

/// The legitimate path still works: a peer inside the allowlist has its header
/// honoured exactly as before.
#[tokio::test]
async fn trusted_peer_header_is_honoured() {
    let backend = spawn_fake_backend().await;
    let proxy_addr =
        spawn_proxy_once_with_trust(backend.addr, allow_all_guardian(), trust_loopback()).await;

    let _sock = connect_and_send(proxy_addr, &forged_connection_bytes())
        .await
        .unwrap();

    let capture = with_timeout(Duration::from_secs(5), backend.captured)
        .await
        .expect("backend never received a startup message")
        .expect("capture channel dropped");

    assert_eq!(
        capture.param("application_name").as_deref(),
        Some("psql - 203.0.113.99")
    );
}

/// Guardian's IP rules are only as trustworthy as the address they are given.
/// This is the exploit chain from AUDIT.md section 5.1: the shipped
/// guardian.yaml grants 127.0.0.1 an ALLOW action that bypasses every query
/// rule, so forging that address from off-host used to disable the firewall.
#[tokio::test]
async fn forged_loopback_cannot_be_used_to_reach_an_allow_rule() {
    let backend = spawn_fake_backend().await;
    let proxy_addr =
        spawn_proxy_once_with_trust(backend.addr, allow_all_guardian(), trust_nobody_local()).await;

    let mut wire = proxy_v1_header("127.0.0.1", 12345);
    wire.extend_from_slice(&startup_message(&[
        ("user", "postgres"),
        ("database", "postgres"),
    ]));

    let _sock = connect_and_send(proxy_addr, &wire).await.unwrap();

    let reached_backend = with_timeout(Duration::from_millis(500), backend.captured).await;
    assert!(
        reached_backend.is_none(),
        "a forged loopback header from an untrusted peer was accepted"
    );
}

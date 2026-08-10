//! AUDIT.md findings #13, #14 and #20: attacker-controlled lengths drive
//! unbounded allocation, and nothing in the connection path has a timeout.

mod common;

use std::time::Duration;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// How long a well-behaved handshake could plausibly take. Every test here
/// asserts the proxy gives up well inside this.
const PATIENCE: Duration = Duration::from_secs(4);

async fn assert_closed_within(sock: &mut TcpStream, what: &str) {
    let mut buf = [0u8; 256];
    let outcome = with_timeout(PATIENCE, sock.read(&mut buf)).await;
    match outcome {
        None => panic!("{}: proxy never closed the connection", what),
        Some(Ok(0)) => {}
        Some(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Some(Ok(n)) => {
            // An ErrorResponse is an acceptable, and nicer, way to refuse.
            assert_eq!(
                buf[0], b'E',
                "{}: expected close or ErrorResponse, got {:?}",
                what,
                &buf[..n]
            );
        }
        Some(Err(e)) => panic!("{}: unexpected error {e}", what),
    }
}

/// Finding #13. The declared length is used to size a buffer before a single
/// payload byte is read, so a client can ask the proxy to allocate up to 4 GiB
/// per connection. 64 MiB here keeps the test survivable while still being
/// far past anything legitimate; PostgreSQL itself caps startup packets at
/// 10000 bytes.
#[tokio::test]
async fn oversized_startup_length_is_refused() {
    let backend = spawn_fake_backend().await;
    let proxy_addr = spawn_proxy_once(backend.addr, allow_all_guardian()).await;

    let mut sock = TcpStream::connect(proxy_addr).await.unwrap();
    sock.write_all(&proxy_v1_header("10.0.0.5", 5555)).await.unwrap();
    sock.write_all(&(64u32 * 1024 * 1024).to_be_bytes()).await.unwrap();
    sock.flush().await.unwrap();

    assert_closed_within(&mut sock, "oversized startup length").await;
}

/// A length that cannot contain even a protocol version.
#[tokio::test]
async fn undersized_startup_length_is_refused() {
    let backend = spawn_fake_backend().await;
    let proxy_addr = spawn_proxy_once(backend.addr, allow_all_guardian()).await;

    let mut sock = TcpStream::connect(proxy_addr).await.unwrap();
    sock.write_all(&proxy_v1_header("10.0.0.5", 5555)).await.unwrap();
    sock.write_all(&4u32.to_be_bytes()).await.unwrap();
    sock.flush().await.unwrap();

    assert_closed_within(&mut sock, "undersized startup length").await;

    let reached = with_timeout(Duration::from_millis(300), backend.captured).await;
    assert!(reached.is_none(), "a 4-byte startup packet reached the backend");
}

/// Finding #14. The PROXY header is read with `read_until(b'\n')` into an
/// unbounded Vec. A v1 header is at most 107 bytes by specification; a client
/// that never sends a newline grows the buffer without limit.
#[tokio::test]
async fn oversized_proxy_header_is_refused() {
    let backend = spawn_fake_backend().await;
    let proxy_addr = spawn_proxy_once(backend.addr, allow_all_guardian()).await;

    let mut sock = TcpStream::connect(proxy_addr).await.unwrap();
    let junk = vec![b'A'; 1024 * 1024];
    // Ignore write errors: once the proxy refuses, the socket goes away.
    let _ = sock.write_all(b"PROXY TCP4 ").await;
    let _ = sock.write_all(&junk).await;
    let _ = sock.flush().await;

    assert_closed_within(&mut sock, "oversized proxy header").await;
}

/// Finding #20. A client that completes the TCP handshake and then says
/// nothing holds a task and its file descriptors indefinitely.
#[tokio::test]
async fn silent_client_is_disconnected_by_the_handshake_timeout() {
    let backend = spawn_fake_backend().await;
    let proxy_addr = spawn_proxy_once(backend.addr, allow_all_guardian()).await;

    let mut sock = TcpStream::connect(proxy_addr).await.unwrap();
    assert_closed_within(&mut sock, "silent client").await;
}

/// A client that sends a valid PROXY header and then stalls before the startup
/// message must also be reaped.
#[tokio::test]
async fn client_stalling_after_the_proxy_header_is_disconnected() {
    let backend = spawn_fake_backend().await;
    let proxy_addr = spawn_proxy_once(backend.addr, allow_all_guardian()).await;

    let mut sock = TcpStream::connect(proxy_addr).await.unwrap();
    sock.write_all(&proxy_v1_header("10.0.0.5", 5555)).await.unwrap();
    sock.flush().await.unwrap();

    assert_closed_within(&mut sock, "stall after proxy header").await;
}

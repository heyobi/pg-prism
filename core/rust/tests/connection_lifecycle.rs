//! AUDIT.md findings #2, #19, #21 and #37: protocol messages the proxy did not
//! recognise, errors it reported by hanging up, and connections it never
//! finished closing.

mod common;

use std::time::Duration;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const WAIT: Duration = Duration::from_secs(5);

const CANCEL_REQUEST_CODE: u32 = 80877102;
const GSSENC_REQUEST_CODE: u32 = 80877104;

fn startup_phase_packet(code: u32, tail: &[u8]) -> Vec<u8> {
    let mut payload = code.to_be_bytes().to_vec();
    payload.extend_from_slice(tail);
    let mut msg = ((payload.len() + 4) as u32).to_be_bytes().to_vec();
    msg.extend_from_slice(&payload);
    msg
}

/// A CancelRequest as libpq sends it: sixteen bytes total, carrying the backend
/// process id and secret key from BackendKeyData.
fn cancel_request(pid: u32, key: u32) -> Vec<u8> {
    let mut tail = pid.to_be_bytes().to_vec();
    tail.extend_from_slice(&key.to_be_bytes());
    startup_phase_packet(CANCEL_REQUEST_CODE, &tail)
}

// ---------------------------------------------------------------------------
// Finding #2: CancelRequest
// ---------------------------------------------------------------------------

/// A CancelRequest opens a second connection and carries a different startup
/// packet. The proxy did not recognise the code, so it ran the sixteen bytes
/// through the application_name rewriter, which split the binary pid and key on
/// their zero bytes and appended parameters. PostgreSQL rejected the result and
/// cancellation silently did nothing.
///
/// The bytes must arrive exactly as sent.
#[tokio::test]
async fn cancel_request_is_forwarded_verbatim() {
    let backend = spawn_fake_backend().await;
    let proxy = spawn_proxy_once(backend.addr, allow_all_guardian()).await;

    let request = cancel_request(4242, 0xdead_beef);

    let mut wire = proxy_v1_header("203.0.113.99", 40001);
    wire.extend_from_slice(&request);
    let _sock = connect_and_send(proxy, &wire).await.unwrap();

    let capture = with_timeout(WAIT, backend.captured)
        .await
        .expect("the CancelRequest never reached the backend")
        .expect("capture dropped");

    assert_eq!(capture.declared_len, 16, "length prefix was rewritten");

    let mut expected_payload = CANCEL_REQUEST_CODE.to_be_bytes().to_vec();
    expected_payload.extend_from_slice(&4242u32.to_be_bytes());
    expected_payload.extend_from_slice(&0xdead_beefu32.to_be_bytes());
    assert_eq!(
        capture.payload, expected_payload,
        "the CancelRequest body was modified"
    );
}

/// A CancelRequest carries no user or database, so Guardian has nothing to
/// evaluate and must not deny it. A DENY-everything ruleset must not stop a
/// cancellation.
#[tokio::test]
async fn cancel_request_is_not_subject_to_guardian_connection_rules() {
    let backend = spawn_fake_backend().await;
    let proxy = spawn_proxy_once(backend.addr, deny_all_guardian()).await;

    let mut wire = proxy_v1_header("203.0.113.99", 40001);
    wire.extend_from_slice(&cancel_request(99, 1));
    let _sock = connect_and_send(proxy, &wire).await.unwrap();

    let capture = with_timeout(WAIT, backend.captured)
        .await
        .expect("Guardian blocked a CancelRequest")
        .expect("capture dropped");
    assert_eq!(capture.declared_len, 16);
}

// ---------------------------------------------------------------------------
// GSSENCRequest
// ---------------------------------------------------------------------------

/// The proxy cannot relay GSSAPI encryption, so it refuses with 'N' and the
/// client falls back. Asserting it rather than assuming it.
#[tokio::test]
async fn gssenc_request_is_refused_then_the_startup_proceeds() {
    let backend = spawn_fake_backend().await;
    let proxy = spawn_proxy_once(backend.addr, allow_all_guardian()).await;

    let mut wire = proxy_v1_header("203.0.113.99", 40001);
    wire.extend_from_slice(&startup_phase_packet(GSSENC_REQUEST_CODE, &[]));
    let mut sock = connect_and_send(proxy, &wire).await.unwrap();

    let mut reply = [0u8; 1];
    with_timeout(WAIT, sock.read_exact(&mut reply))
        .await
        .expect("no reply to GSSENCRequest")
        .expect("read failed");
    assert_eq!(reply[0], b'N', "expected a refusal");

    // The client now continues with a normal startup on the same socket.
    sock.write_all(&startup_message(&[
        ("user", "postgres"),
        ("database", "postgres"),
        ("application_name", "after-gssenc"),
    ]))
    .await
    .unwrap();
    sock.flush().await.unwrap();

    let capture = with_timeout(WAIT, backend.captured)
        .await
        .expect("the startup after GSSENCRequest never arrived")
        .expect("capture dropped");
    assert_eq!(
        capture.param("application_name").as_deref(),
        Some("after-gssenc - 203.0.113.99")
    );
}

// ---------------------------------------------------------------------------
// Finding #21 and #37: telling the client what went wrong
// ---------------------------------------------------------------------------

/// When the backend cannot be reached the client used to get a bare FIN, which
/// psql reports as "server closed the connection unexpectedly" and JDBC as a
/// generic socket error. It should get an ErrorResponse saying so.
#[tokio::test]
async fn unreachable_backend_produces_an_error_response() {
    // Bind and immediately drop, so the port is closed but was never in use.
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };

    let proxy = spawn_proxy_once(dead, allow_all_guardian()).await;

    let mut wire = proxy_v1_header("203.0.113.99", 40001);
    wire.extend_from_slice(&startup_message(&[
        ("user", "postgres"),
        ("database", "postgres"),
    ]));
    let mut sock = connect_and_send(proxy, &wire).await.unwrap();

    let mut buf = vec![0u8; 512];
    let n = with_timeout(WAIT, sock.read(&mut buf))
        .await
        .expect("the proxy never answered")
        .expect("read failed");

    assert!(n > 0, "the proxy closed without an ErrorResponse");
    assert_eq!(
        buf[0],
        b'E',
        "expected an ErrorResponse, got {:?}",
        &buf[..n]
    );

    let body = String::from_utf8_lossy(&buf[5..n]);
    assert!(
        body.contains("08006"),
        "expected SQLSTATE 08006 connection_failure, got {:?}",
        body
    );
    assert!(
        body.contains("VERROR"),
        "ErrorResponse is missing the non-localised severity field V: {:?}",
        body
    );
}

// ---------------------------------------------------------------------------
// Finding #19: half-close propagation
// ---------------------------------------------------------------------------

/// When the client goes away, the upstream connection must be closed too.
/// Previously the proxy waited for *both* directions to finish, so a client
/// that disappeared while the backend was idle left a task and two descriptors
/// alive until the operating system's TCP timeout.
#[tokio::test]
async fn client_disconnect_closes_the_upstream_connection() {
    let mut backend = spawn_fake_backend().await;
    let proxy = spawn_proxy_once(backend.addr, allow_all_guardian()).await;

    let mut wire = proxy_v1_header("203.0.113.99", 40001);
    wire.extend_from_slice(&startup_message(&[
        ("user", "postgres"),
        ("database", "postgres"),
    ]));
    let sock = connect_and_send(proxy, &wire).await.unwrap();

    let captured = std::mem::replace(&mut backend.captured, tokio::sync::oneshot::channel().1);
    with_timeout(WAIT, captured)
        .await
        .expect("startup never arrived")
        .expect("capture dropped");

    // The client vanishes.
    drop(sock);

    with_timeout(WAIT, backend.saw_eof)
        .await
        .expect("the backend never saw EOF: the upstream connection leaked")
        .expect("eof signal dropped");
}

/// And the other direction: when PostgreSQL hangs up, the client must find out
/// rather than waiting on a socket nobody will ever write to.
#[tokio::test]
async fn backend_disconnect_closes_the_client_connection() {
    let backend = spawn_fake_backend_closing_after_startup().await;
    let proxy = spawn_proxy_once(backend.addr, allow_all_guardian()).await;

    let mut wire = proxy_v1_header("203.0.113.99", 40001);
    wire.extend_from_slice(&startup_message(&[
        ("user", "postgres"),
        ("database", "postgres"),
    ]));
    let mut sock = connect_and_send(proxy, &wire).await.unwrap();

    let mut buf = [0u8; 64];
    match with_timeout(WAIT, sock.read(&mut buf))
        .await
        .expect("the client was never told the backend had gone")
    {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Ok(n) => panic!("unexpected data from a dead backend: {:?}", &buf[..n]),
        Err(e) => panic!("unexpected error: {e}"),
    }
}

/// A client that half-closes its write side must still receive the results of
/// work already in flight. This is the case a naive select! would truncate.
#[tokio::test]
async fn a_half_closed_client_still_receives_pending_responses() {
    let mut backend = spawn_fake_backend().await;
    let proxy = spawn_proxy_once(backend.addr, allow_all_guardian()).await;

    let mut wire = proxy_v1_header("203.0.113.99", 40001);
    wire.extend_from_slice(&startup_message(&[
        ("user", "postgres"),
        ("database", "postgres"),
    ]));
    let mut sock = TcpStream::connect(proxy).await.unwrap();
    sock.write_all(&wire).await.unwrap();
    sock.flush().await.unwrap();

    let captured = std::mem::replace(&mut backend.captured, tokio::sync::oneshot::channel().1);
    with_timeout(WAIT, captured)
        .await
        .expect("startup never arrived")
        .expect("capture dropped");

    // Client says "I am done sending" but keeps reading.
    sock.shutdown().await.unwrap();

    // The backend answers afterwards. The proxy must still deliver it.
    backend
        .reply(b"Z\x00\x00\x00\x05I")
        .await
        .expect("could not write from the backend");

    let mut buf = [0u8; 16];
    let n = with_timeout(WAIT, sock.read(&mut buf))
        .await
        .expect("nothing arrived after the client half-closed")
        .expect("read failed");
    assert_eq!(
        &buf[..n],
        b"Z\x00\x00\x00\x05I",
        "the response was truncated by the half-close"
    );
}

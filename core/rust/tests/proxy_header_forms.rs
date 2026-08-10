//! Which forms of the PROXY protocol header the proxy actually accepts.
//!
//! Written for the A7 documentation pass: the README and the architecture guide
//! both make claims about IPv6 and about `send-proxy-v2`, and neither claim had
//! anything behind it. These tests are what turns them from assertions into
//! statements about observed behaviour.

mod common;

use std::time::Duration;

use common::*;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

const WAIT: Duration = Duration::from_secs(5);

fn startup(params: &[(&str, &str)]) -> Vec<u8> {
    let mut payload = 196608u32.to_be_bytes().to_vec();
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

async fn assert_refused(sock: &mut TcpStream, what: &str) {
    let mut buf = [0u8; 256];
    match with_timeout(WAIT, sock.read(&mut buf)).await {
        None => panic!("{}: the proxy neither answered nor closed", what),
        Some(Ok(0)) => {}
        Some(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Some(Ok(n)) => assert_eq!(buf[0], b'E', "{}: got {:?}", what, &buf[..n]),
        Some(Err(e)) => panic!("{}: unexpected error {e}", what),
    }
}

/// A `PROXY TCP6` line carries an IPv6 literal in the same third field. The
/// reader is address-family agnostic — it takes the field as text — so this
/// should work, and until now nothing demonstrated that it did.
#[tokio::test]
async fn an_ipv6_proxy_header_yields_the_ipv6_client_address() {
    let backend = spawn_fake_backend().await;
    let proxy = spawn_proxy_once(backend.addr, allow_all_guardian()).await;

    let header = b"PROXY TCP6 2001:db8::dead:beef ::1 40001 5433\r\n";
    let mut wire = header.to_vec();
    wire.extend_from_slice(&startup(&[
        ("user", "app_user"),
        ("database", "shop"),
        ("application_name", "psql"),
    ]));
    let _sock = connect_and_send(proxy, &wire).await.unwrap();

    let capture = with_timeout(WAIT, backend.captured)
        .await
        .expect("startup never arrived")
        .expect("capture dropped");

    assert_eq!(
        capture.param("application_name").as_deref(),
        Some("psql - 2001:db8::dead:beef"),
        "an IPv6 client address must survive the header parse and the injection"
    );
}

/// A full-length IPv6 literal is 39 characters, and the injected suffix is
/// ` - ` plus that. Worth pinning because the truncation budget is the part of
/// this code most likely to be quietly wrong.
#[tokio::test]
async fn a_full_length_ipv6_address_still_fits_the_namedatalen_budget() {
    let backend = spawn_fake_backend().await;
    let proxy = spawn_proxy_once(backend.addr, allow_all_guardian()).await;

    let addr = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    let mut wire = format!("PROXY TCP6 {} ::1 40001 5433\r\n", addr).into_bytes();
    wire.extend_from_slice(&startup(&[
        ("user", "app_user"),
        ("database", "shop"),
        ("application_name", "a-fairly-long-application-name"),
    ]));
    let _sock = connect_and_send(proxy, &wire).await.unwrap();

    let capture = with_timeout(WAIT, backend.captured)
        .await
        .expect("startup never arrived")
        .expect("capture dropped");

    let name = capture
        .param("application_name")
        .expect("no application_name");
    assert!(
        name.ends_with(&format!(" - {}", addr)),
        "the address was truncated: {:?}",
        name
    );
    assert!(name.len() <= 63, "{} bytes: {:?}", name.len(), name);
}

/// **`send-proxy-v2` does not work, and fails cleanly.**
///
/// The v2 header is binary and begins with the signature
/// `\r\n\r\n\0\r\nQUIT\n`. The v1 reader scans to the first `\n` — which is the
/// second byte — and then rejects the line because it does not start with
/// `PROXY`. So the connection is refused rather than misparsed, which is the
/// good outcome, but the README must not tell anyone to configure `send-proxy-v2`.
#[tokio::test]
async fn a_proxy_v2_header_is_refused_rather_than_misparsed() {
    let backend = spawn_fake_backend().await;
    let proxy = spawn_proxy_once(backend.addr, allow_all_guardian()).await;

    // v2 signature, version/command 0x21, TCP over IPv4 0x11, length 12,
    // then src/dst addresses and ports.
    let mut wire: Vec<u8> = vec![
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
    ];
    wire.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
    wire.extend_from_slice(&[203, 0, 113, 99]); // source address
    wire.extend_from_slice(&[127, 0, 0, 1]); // destination address
    wire.extend_from_slice(&40001u16.to_be_bytes());
    wire.extend_from_slice(&5433u16.to_be_bytes());
    wire.extend_from_slice(&startup(&[("user", "app_user"), ("database", "shop")]));

    let mut sock = connect_and_send(proxy, &wire).await.unwrap();
    assert_refused(&mut sock, "PROXY v2 header").await;

    let reached = with_timeout(Duration::from_millis(300), backend.captured).await;
    assert!(
        reached.is_none(),
        "a v2 header must not reach the backend as if it had been understood"
    );
}

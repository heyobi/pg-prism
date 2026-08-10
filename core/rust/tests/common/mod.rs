//! Shared test harness: an in-process fake PostgreSQL backend and a helper that
//! runs one connection through the proxy.
//!
//! The fake backend exists for speed and determinism. It is deliberately *not*
//! the only backend the suite runs against — see `tests/real_postgres.rs`, which
//! exercises the same paths against a real server in CI. A proxy tested only
//! against a backend written by the same author encodes that author's protocol
//! assumptions, which are exactly the assumptions that produced the bugs in
//! AUDIT.md.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use pg_prism_rust::guardian::{Action, Guardian, Rule};
use pg_prism_rust::limits::Limits;
use pg_prism_rust::proxy::ProxyConfig;
use pg_prism_rust::trust::TrustedProxies;

/// The first startup packet the backend received, split into its length prefix
/// and payload, exactly as it arrived on the wire.
#[derive(Debug, Clone)]
pub struct StartupCapture {
    pub declared_len: u32,
    pub payload: Vec<u8>,
}

impl StartupCapture {
    /// The startup parameters as (key, value) pairs. Assumes a protocol-3.0
    /// layout: 4 version bytes, then NUL-terminated key/value pairs, then a
    /// final NUL.
    pub fn params(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        if self.payload.len() < 4 {
            return out;
        }
        let mut section = &self.payload[4..];
        if let Some((last, rest)) = section.split_last() {
            if *last == 0 {
                section = rest;
            }
        }
        let parts: Vec<&[u8]> = section.split(|&b| b == 0).collect();
        let mut i = 0;
        while i + 1 < parts.len() {
            out.push((
                String::from_utf8_lossy(parts[i]).to_string(),
                String::from_utf8_lossy(parts[i + 1]).to_string(),
            ));
            i += 2;
        }
        out
    }

    pub fn param(&self, key: &str) -> Option<String> {
        self.params()
            .into_iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    pub fn protocol_version(&self) -> Option<u32> {
        if self.payload.len() < 4 {
            return None;
        }
        Some(u32::from_be_bytes([
            self.payload[0],
            self.payload[1],
            self.payload[2],
            self.payload[3],
        ]))
    }
}

/// One post-startup message as it arrived at the backend.
#[derive(Debug, Clone)]
pub struct Frame {
    pub msg_type: u8,
    pub payload: Vec<u8>,
}

impl Frame {
    /// The payload as text with any trailing NUL removed, for Query messages.
    pub fn text(&self) -> String {
        let body = self.payload.strip_suffix(&[0]).unwrap_or(&self.payload);
        String::from_utf8_lossy(body).to_string()
    }
}

/// A fake PostgreSQL server that captures the startup packet and then every
/// subsequent message frame the proxy forwards.
pub struct FakeBackend {
    pub addr: SocketAddr,
    pub captured: oneshot::Receiver<StartupCapture>,
    pub frames: tokio::sync::mpsc::UnboundedReceiver<Frame>,
    /// Fires when the backend's read loop ends, i.e. when the proxy closed the
    /// upstream connection or shut down its write half. This is how the tests
    /// observe half-close propagation rather than inferring it.
    pub saw_eof: oneshot::Receiver<()>,
    replies: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
}

impl FakeBackend {
    /// Waits for the next forwarded message, or returns None if none arrives.
    pub async fn next_frame(&mut self, within: Duration) -> Option<Frame> {
        tokio::time::timeout(within, self.frames.recv())
            .await
            .ok()
            .flatten()
    }

    /// Sends bytes from the backend towards the client, the way a real server
    /// would answer a query.
    pub async fn reply(&self, bytes: &[u8]) -> Result<(), &'static str> {
        self.replies
            .send(bytes.to_vec())
            .map_err(|_| "backend writer is gone")
    }
}

pub async fn spawn_fake_backend() -> FakeBackend {
    spawn_fake_backend_inner(BackendBehaviour::StayOpen).await
}

/// A backend that hangs up as soon as it has read the startup packet, so tests
/// can observe what the proxy does when PostgreSQL goes away.
pub async fn spawn_fake_backend_closing_after_startup() -> FakeBackend {
    spawn_fake_backend_inner(BackendBehaviour::CloseAfterStartup).await
}

#[derive(Clone, Copy, PartialEq)]
enum BackendBehaviour {
    StayOpen,
    CloseAfterStartup,
}

async fn spawn_fake_backend_inner(behaviour: BackendBehaviour) -> FakeBackend {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let (frame_tx, frame_rx) = tokio::sync::mpsc::unbounded_channel();
    let (eof_tx, eof_rx) = oneshot::channel();
    let (reply_tx, mut reply_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

    tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };

        let mut len_bytes = [0u8; 4];
        if sock.read_exact(&mut len_bytes).await.is_err() {
            return;
        }
        let declared_len = u32::from_be_bytes(len_bytes);
        let payload_len = declared_len.saturating_sub(4) as usize;
        let mut payload = vec![0u8; payload_len];
        if sock.read_exact(&mut payload).await.is_err() {
            return;
        }
        let _ = tx.send(StartupCapture {
            declared_len,
            payload,
        });

        if behaviour == BackendBehaviour::CloseAfterStartup {
            drop(sock);
            let _ = eof_tx.send(());
            return;
        }

        let (mut rd, mut wr) = sock.into_split();

        tokio::spawn(async move {
            while let Some(bytes) = reply_rx.recv().await {
                if wr.write_all(&bytes).await.is_err() {
                    break;
                }
                let _ = wr.flush().await;
            }
        });

        // Read normal message frames: one type byte, a four-byte length that
        // includes itself, and the payload.
        loop {
            let mut type_byte = [0u8; 1];
            if rd.read_exact(&mut type_byte).await.is_err() {
                break;
            }
            let mut len_bytes = [0u8; 4];
            if rd.read_exact(&mut len_bytes).await.is_err() {
                break;
            }
            let body_len = u32::from_be_bytes(len_bytes).saturating_sub(4) as usize;
            let mut body = vec![0u8; body_len];
            if rd.read_exact(&mut body).await.is_err() {
                break;
            }
            if frame_tx
                .send(Frame {
                    msg_type: type_byte[0],
                    payload: body,
                })
                .is_err()
            {
                break;
            }
        }

        // Reached only when the client side of the upstream connection ended,
        // which is what half-close propagation is supposed to cause.
        let _ = eof_tx.send(());
    });

    FakeBackend {
        addr,
        captured: rx,
        frames: frame_rx,
        saw_eof: eof_rx,
        replies: reply_tx,
    }
}

/// Accepts exactly one connection on an ephemeral port and runs it through
/// `handle_client`. Returns the address a client should connect to.
///
/// Tests run over loopback, so the default allowlist trusts the test client.
/// Pass an allowlist that excludes loopback to exercise the rejection path.
pub async fn spawn_proxy_once(pg_addr: SocketAddr, guardian: Arc<Guardian>) -> SocketAddr {
    spawn_proxy_once_with_trust(pg_addr, guardian, trust_loopback()).await
}

pub async fn spawn_proxy_once_with_trust(
    pg_addr: SocketAddr,
    guardian: Arc<Guardian>,
    trusted: Arc<TrustedProxies>,
) -> SocketAddr {
    spawn_proxy_once_with_config(ProxyConfig {
        pg_addr: pg_addr.to_string(),
        guardian,
        tls_acceptor: None,
        trusted,
        limits: test_limits(),
    })
    .await
}

pub async fn spawn_proxy_once_with_config(cfg: ProxyConfig) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = Arc::new(cfg);

    tokio::spawn(async move {
        let Ok((sock, _)) = listener.accept().await else {
            return;
        };
        let _ = pg_prism_rust::proxy::handle_client(sock, cfg).await;
    });

    addr
}

/// Serves connections until dropped. Needed wherever a single logical client
/// opens more than one socket, which CancelRequest does by design.
pub async fn spawn_proxy_serving(cfg: ProxyConfig) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = Arc::new(cfg);

    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let cfg = cfg.clone();
            tokio::spawn(async move {
                let _ = pg_prism_rust::proxy::handle_client(sock, cfg).await;
            });
        }
    });

    addr
}

/// Production limits with the timeouts shortened, so timeout behaviour is
/// actually exercised instead of making the suite take ten seconds per case.
pub fn test_limits() -> Limits {
    Limits {
        handshake_timeout: Duration::from_millis(750),
        upstream_connect_timeout: Duration::from_millis(750),
        drain_timeout: Duration::from_millis(750),
        ..Limits::default()
    }
}

pub fn allow_all_guardian() -> Arc<Guardian> {
    Arc::new(Guardian { rules: vec![] })
}

/// A ruleset that denies every connection, used to prove that message types
/// carrying no user or database are not subject to connection rules.
pub fn deny_all_guardian() -> Arc<Guardian> {
    Arc::new(Guardian {
        rules: vec![Rule {
            name: "deny-all".to_string(),
            action: Action::DENY,
            ips: Some(vec!["0.0.0.0/0".to_string(), "::/0".to_string()]),
            users: None,
            databases: None,
            time_range: None,
            block_queries: None,
            block_tables: None,
        }],
    })
}

pub fn trust_loopback() -> Arc<TrustedProxies> {
    Arc::new(TrustedProxies::parse(pg_prism_rust::trust::DEFAULT_TRUSTED_PROXIES).unwrap())
}

/// An allowlist that deliberately excludes the loopback address the tests
/// connect from, so the peer looks like an untrusted third party.
pub fn trust_nobody_local() -> Arc<TrustedProxies> {
    Arc::new(TrustedProxies::parse("10.11.12.0/24").unwrap())
}

/// A protocol-3.0 StartupMessage with the given parameters, framed with its
/// length prefix.
pub fn startup_message(params: &[(&str, &str)]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&196608u32.to_be_bytes());
    for (k, v) in params {
        payload.extend_from_slice(k.as_bytes());
        payload.push(0);
        payload.extend_from_slice(v.as_bytes());
        payload.push(0);
    }
    payload.push(0);

    let mut msg = Vec::new();
    msg.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
    msg.extend_from_slice(&payload);
    msg
}

pub fn proxy_v1_header(client_ip: &str, client_port: u16) -> Vec<u8> {
    format!(
        "PROXY TCP4 {} 127.0.0.1 {} 5433\r\n",
        client_ip, client_port
    )
    .into_bytes()
}

/// Connects, writes the given bytes, and returns the socket.
pub async fn connect_and_send(addr: SocketAddr, bytes: &[u8]) -> std::io::Result<TcpStream> {
    let mut sock = TcpStream::connect(addr).await?;
    sock.write_all(bytes).await?;
    sock.flush().await?;
    Ok(sock)
}

pub async fn with_timeout<T>(d: Duration, fut: impl std::future::Future<Output = T>) -> Option<T> {
    tokio::time::timeout(d, fut).await.ok()
}

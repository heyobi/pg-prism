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

use pg_prism_rust::guardian::Guardian;
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

/// A fake PostgreSQL server that captures the first length-prefixed packet it
/// receives and then holds the connection open.
pub struct FakeBackend {
    pub addr: SocketAddr,
    pub captured: oneshot::Receiver<StartupCapture>,
}

pub async fn spawn_fake_backend() -> FakeBackend {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();

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
        // Hold the socket so the proxy's forwarding tasks stay alive.
        let mut sink = [0u8; 1024];
        loop {
            match sock.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });

    FakeBackend { addr, captured: rx }
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
        ..Limits::default()
    }
}

pub fn allow_all_guardian() -> Arc<Guardian> {
    Arc::new(Guardian { rules: vec![] })
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

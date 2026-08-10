//! Per-connection handling: PROXY header, startup negotiation, forwarding.

use std::error::Error;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_native_tls::TlsAcceptor;

use crate::guardian::{Action, ConnectionContext, Guardian};
use crate::limits::Limits;
use crate::protocol::{
    extract_user_db, inject_ip_startup, make_error_response, process_extended_query,
    process_simple_query, GSSENC_REQUEST, SSL_REQUEST, STARTUP_MESSAGE,
};
use crate::trust::{RejectionLog, TrustedProxies};

/// Process-wide throttle for "untrusted peer" warnings. Rejections are
/// attacker-triggerable, so one log line per rejected connection would be a log
/// amplification vector.
static UNTRUSTED_PEER_LOG: std::sync::LazyLock<RejectionLog> =
    std::sync::LazyLock::new(RejectionLog::default);

// Trait alias for dynamic read/write stream (used for plain TcpStream and TlsStream)
pub trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

/// Everything a connection needs, shared behind one `Arc` rather than four.
pub struct ProxyConfig {
    pub pg_addr: String,
    pub guardian: Arc<Guardian>,
    pub tls_acceptor: Option<Arc<TlsAcceptor>>,
    pub trusted: Arc<TrustedProxies>,
    pub limits: Limits,
}

type BoxError = Box<dyn Error + Send + Sync>;

/// What went wrong before the connection was established.
#[derive(Debug)]
enum HandshakeError {
    /// The client broke the protocol. It gets an ErrorResponse.
    Protocol(String),
    /// Transport-level failure or a peer that simply went away.
    Io(BoxError),
}

impl From<std::io::Error> for HandshakeError {
    fn from(e: std::io::Error) -> Self {
        HandshakeError::Io(Box::new(e))
    }
}

struct Handshake {
    stream: Box<dyn AsyncReadWrite + Unpin + Send>,
    payload: Vec<u8>,
    client_ip: String,
}

pub async fn handle_client(
    client_socket: TcpStream,
    cfg: Arc<ProxyConfig>,
) -> Result<(), BoxError> {
    // 0. Is this peer allowed to speak the PROXY protocol to us?
    //
    // The header is an unauthenticated assertion. It is only meaningful from a
    // load balancer we operate, so the check happens here, before a single byte
    // of the header is parsed. Anything else is refused without reading: the
    // listener exists solely to receive HAProxy's send-proxy traffic, and a
    // connection from elsewhere is a misconfiguration or an attempt to forge a
    // source address.
    let peer_ip = client_socket.peer_addr()?.ip();
    if !cfg.trusted.is_trusted(peer_ip) {
        if let Some(suppressed) = UNTRUSTED_PEER_LOG.should_log() {
            if suppressed > 0 {
                log::warn!(
                    "Refused connection from {}: not in TRUSTED_PROXIES ({}). \
                     {} further rejections suppressed.",
                    peer_ip,
                    cfg.trusted.spec(),
                    suppressed
                );
            } else {
                log::warn!(
                    "Refused connection from {}: not in TRUSTED_PROXIES ({}). \
                     Only load balancers listed there may send a PROXY header; \
                     clients must not connect to this port directly.",
                    peer_ip,
                    cfg.trusted.spec()
                );
            }
        }
        return Ok(());
    }

    // 1-3. Handshake, under a single deadline.
    //
    // A legitimate client completes the PROXY header, SSL negotiation and the
    // startup message in milliseconds. Without a deadline, a client that opens
    // a socket and then says nothing holds a task and its descriptors forever.
    let handshake = match timeout(
        cfg.limits.handshake_timeout,
        perform_handshake(client_socket, &cfg),
    )
    .await
    {
        Err(_elapsed) => {
            log::warn!(
                "Handshake from {} timed out after {:?}",
                peer_ip,
                cfg.limits.handshake_timeout
            );
            return Ok(());
        }
        Ok(Err(HandshakeError::Protocol(msg))) => {
            log::warn!("Protocol error from {}: {}", peer_ip, msg);
            return Ok(());
        }
        Ok(Err(HandshakeError::Io(e))) => return Err(e),
        Ok(Ok(h)) => h,
    };

    let Handshake {
        mut stream,
        payload,
        client_ip,
    } = handshake;

    // 4. Guardian connection check.
    let mut guardian_context = ConnectionContext {
        action: Action::INSPECT,
        block_queries: vec![],
        block_tables: vec![],
    };
    let mut context_initialized = false;

    if payload.len() >= 4 {
        let protocol = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        if protocol == STARTUP_MESSAGE {
            let (user, db) = extract_user_db(&payload);
            log::info!("Startup: User='{}', DB='{}'", user, db);

            guardian_context = cfg.guardian.check_connection(&client_ip, &user, &db);

            if guardian_context.action == Action::DENY {
                log::warn!(
                    "Guardian: Connection denied for {} (User: {}, DB: {})",
                    client_ip,
                    user,
                    db
                );
                let err_packet = make_error_response(
                    &format!(
                        "Connection denied by PG-Prism Guardian for IP: {}",
                        client_ip
                    ),
                    "28000",
                );
                stream.write_all(&err_packet).await?;
                stream.flush().await?;
                return Ok(());
            }
            context_initialized = true;
        }
    }

    // 5. Connect to upstream PostgreSQL, under its own deadline.
    let pg_socket = match timeout(
        cfg.limits.upstream_connect_timeout,
        TcpStream::connect(&cfg.pg_addr),
    )
    .await
    {
        Err(_elapsed) => {
            log::error!(
                "Upstream {} did not accept a connection within {:?}",
                cfg.pg_addr,
                cfg.limits.upstream_connect_timeout
            );
            return Ok(());
        }
        Ok(Err(e)) => {
            log::error!("Upstream {} unreachable: {}", cfg.pg_addr, e);
            return Ok(());
        }
        Ok(Ok(s)) => s,
    };

    if let Err(e) = pg_socket.set_nodelay(true) {
        log::warn!("Failed to set TCP_NODELAY on pg socket: {}", e);
    }
    let (mut pg_read_half, mut pg_write_half) = pg_socket.into_split();

    // 6. Send the rewritten startup message.
    log::info!("Startup Message captured. Injecting IP...");
    let new_payload = inject_ip_startup(&payload, &client_ip);
    let new_len = (new_payload.len() + 4) as u32;
    pg_write_half.write_all(&new_len.to_be_bytes()).await?;
    pg_write_half.write_all(&new_payload).await?;
    pg_write_half.flush().await?;

    // 7. Split client stream
    let (client_read_half, client_write_half) = tokio::io::split(stream);
    let mut client_reader = BufReader::with_capacity(8192, client_read_half);
    let client_write_half = Arc::new(tokio::sync::Mutex::new(client_write_half));

    // 8. Bidirectional Forwarding
    let client_ip_clone = client_ip.clone();

    // Client to Server
    let client_write_half_clone = client_write_half.clone();
    let client_to_server = async move {
        let mut transfer_buf = vec![0u8; 8192];
        let mut query_buf = Vec::with_capacity(1024);

        while let Ok(msg_type) = client_reader.read_u8().await {
            let mut len_bytes = [0u8; 4];
            if client_reader.read_exact(&mut len_bytes).await.is_err() {
                break;
            }
            let msg_len = u32::from_be_bytes(len_bytes);
            let payload_len = (msg_len.saturating_sub(4)) as usize;

            if (msg_type == b'Q' || msg_type == b'P') && payload_len < 1024 {
                query_buf.resize(payload_len, 0);
                if client_reader.read_exact(&mut query_buf).await.is_err() {
                    break;
                }

                // GUARDIAN STAGE 2: Query Check
                if context_initialized && !Guardian::check_query(&query_buf, &guardian_context) {
                    log::warn!("Guardian: Query blocked.");
                    let err_packet =
                        make_error_response("Query blocked by PG-Prism Guardian", "42501");
                    let mut guard = client_write_half_clone.lock().await;
                    if guard.write_all(&err_packet).await.is_ok() {
                        let _ = guard.write_all(b"Z\x00\x00\x00\x05I").await;
                        let _ = guard.flush().await;
                    }
                    continue; // keep connection open
                }

                let (modified, new_payload) = if msg_type == b'Q' {
                    process_simple_query(&query_buf, &client_ip_clone)
                } else {
                    process_extended_query(&query_buf, &client_ip_clone)
                };

                if modified {
                    let new_len = (new_payload.len() + 4) as u32;
                    if pg_write_half.write_u8(msg_type).await.is_err() {
                        break;
                    }
                    if pg_write_half
                        .write_all(&new_len.to_be_bytes())
                        .await
                        .is_err()
                    {
                        break;
                    }
                    if pg_write_half.write_all(&new_payload).await.is_err() {
                        break;
                    }
                } else {
                    if pg_write_half.write_u8(msg_type).await.is_err() {
                        break;
                    }
                    if pg_write_half.write_all(&len_bytes).await.is_err() {
                        break;
                    }
                    if pg_write_half.write_all(&query_buf).await.is_err() {
                        break;
                    }
                }
            } else {
                // Blind Forwarding
                if pg_write_half.write_u8(msg_type).await.is_err() {
                    break;
                }
                if pg_write_half.write_all(&len_bytes).await.is_err() {
                    break;
                }

                let mut left = payload_len;
                while left > 0 {
                    let chunk_len = std::cmp::min(left, transfer_buf.len());
                    if client_reader
                        .read_exact(&mut transfer_buf[..chunk_len])
                        .await
                        .is_err()
                    {
                        break;
                    }
                    if pg_write_half
                        .write_all(&transfer_buf[..chunk_len])
                        .await
                        .is_err()
                    {
                        break;
                    }
                    left -= chunk_len;
                }
            }
            let _ = pg_write_half.flush().await;
        }
        Ok::<(), BoxError>(())
    };

    // Server to Client
    let client_write_half_clone2 = client_write_half.clone();
    let server_to_client = async move {
        let mut buf = [0u8; 8192];
        loop {
            let n = match pg_read_half.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            let mut guard = client_write_half_clone2.lock().await;
            if guard.write_all(&buf[..n]).await.is_err() {
                break;
            }
            let _ = guard.flush().await;
        }
        Ok::<(), BoxError>(())
    };

    let _ = tokio::try_join!(client_to_server, server_to_client);
    Ok(())
}

/// Reads the PROXY header, settles TLS, and reads the startup message.
///
/// Every length that comes off the wire is checked against `cfg.limits` before
/// it is used to size anything.
async fn perform_handshake(
    client_socket: TcpStream,
    cfg: &ProxyConfig,
) -> Result<Handshake, HandshakeError> {
    let mut buf_reader = BufReader::new(client_socket);

    // 1. PROXY protocol v1 header.
    let client_ip = read_proxy_v1_header(&mut buf_reader, cfg.limits.max_proxy_header_len).await?;
    log::info!("Real Client IP: {}", client_ip);

    // 2. SSL / plaintext negotiation, then the startup message.
    let client_stream: Box<dyn AsyncReadWrite + Unpin + Send>;
    let mut len_bytes = [0u8; 4];
    let mut payload = Vec::new();

    loop {
        buf_reader.read_exact(&mut len_bytes).await?;
        let payload_len = checked_startup_len(u32::from_be_bytes(len_bytes), &cfg.limits)?;
        payload.resize(payload_len, 0);
        buf_reader.read_exact(&mut payload).await?;

        let protocol = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);

        match protocol {
            SSL_REQUEST => {
                if let Some(ref acceptor) = cfg.tls_acceptor {
                    log::info!("SSLRequest received. Starting TLS handshake...");
                    let mut raw_socket = buf_reader.into_inner();
                    raw_socket.write_all(b"S").await?;
                    raw_socket.flush().await?;

                    let tls_stream = acceptor
                        .accept(raw_socket)
                        .await
                        .map_err(|e| HandshakeError::Io(Box::new(e)))?;
                    log::info!("TLS connection successfully established.");

                    // Read the startup message inside the TLS session.
                    let mut tls_reader = BufReader::new(
                        Box::new(tls_stream) as Box<dyn AsyncReadWrite + Unpin + Send>
                    );
                    tls_reader.read_exact(&mut len_bytes).await?;
                    let payload_len =
                        checked_startup_len(u32::from_be_bytes(len_bytes), &cfg.limits)?;
                    payload.resize(payload_len, 0);
                    tls_reader.read_exact(&mut payload).await?;

                    client_stream = tls_reader.into_inner();
                    break;
                } else {
                    log::info!("SSLRequest received but SSL is disabled. Forcing plaintext...");
                    let mut raw_socket = buf_reader.into_inner();
                    raw_socket.write_all(b"N").await?;
                    raw_socket.flush().await?;
                    buf_reader = BufReader::new(raw_socket);
                    continue;
                }
            }
            GSSENC_REQUEST => {
                log::info!("GSSENCRequest denied.");
                let mut raw_socket = buf_reader.into_inner();
                raw_socket.write_all(b"N").await?;
                raw_socket.flush().await?;
                buf_reader = BufReader::new(raw_socket);
                continue;
            }
            _ => {
                client_stream = Box::new(buf_reader.into_inner());
                break;
            }
        }
    }

    Ok(Handshake {
        stream: client_stream,
        payload,
        client_ip,
    })
}

/// Validates a startup-phase length prefix and returns the payload size.
///
/// The declared length used to be fed straight into `Vec::resize`, so a client
/// could ask for a 4 GiB allocation before sending a single payload byte.
fn checked_startup_len(msg_len: u32, limits: &Limits) -> Result<usize, HandshakeError> {
    let msg_len = msg_len as usize;
    if msg_len < crate::limits::MIN_STARTUP_PACKET_LENGTH {
        return Err(HandshakeError::Protocol(format!(
            "startup packet length {} is below the {}-byte minimum",
            msg_len,
            crate::limits::MIN_STARTUP_PACKET_LENGTH
        )));
    }
    if msg_len > limits.max_startup_len {
        return Err(HandshakeError::Protocol(format!(
            "startup packet length {} exceeds the {}-byte limit",
            msg_len, limits.max_startup_len
        )));
    }
    Ok(msg_len - 4)
}

/// Reads a PROXY v1 header, one buffered byte at a time, refusing to grow past
/// `max_len`.
///
/// The specification caps a v1 header at 107 bytes including CRLF. The previous
/// implementation used `read_until` into an unbounded `Vec`, so a client that
/// never sent a newline grew the buffer without limit.
async fn read_proxy_v1_header<R>(reader: &mut R, max_len: usize) -> Result<String, HandshakeError>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut header = Vec::with_capacity(max_len);
    loop {
        let byte = reader.read_u8().await?;
        header.push(byte);
        if byte == b'\n' {
            break;
        }
        if header.len() >= max_len {
            return Err(HandshakeError::Protocol(format!(
                "PROXY header exceeded {} bytes without a line terminator",
                max_len
            )));
        }
    }

    let header_str = String::from_utf8_lossy(&header);
    if !header_str.starts_with("PROXY") {
        return Err(HandshakeError::Protocol(
            "connection did not begin with a PROXY protocol v1 header".to_string(),
        ));
    }

    let client_ip = header_str
        .trim()
        .split(' ')
        .nth(2)
        .unwrap_or("")
        .to_string();
    if client_ip.is_empty() {
        return Err(HandshakeError::Protocol(format!(
            "malformed PROXY header: {:?}",
            header_str.trim()
        )));
    }

    Ok(client_ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_length_below_the_minimum_is_rejected() {
        let l = Limits::default();
        for n in [0u32, 1, 4, 7] {
            assert!(checked_startup_len(n, &l).is_err(), "accepted {}", n);
        }
    }

    #[test]
    fn startup_length_above_the_cap_is_rejected() {
        let l = Limits::default();
        assert!(checked_startup_len(10_001, &l).is_err());
        assert!(checked_startup_len(u32::MAX, &l).is_err());
        assert!(checked_startup_len(64 * 1024 * 1024, &l).is_err());
    }

    #[test]
    fn legitimate_startup_lengths_are_accepted() {
        let l = Limits::default();
        assert_eq!(checked_startup_len(8, &l).unwrap(), 4); // SSLRequest
        assert_eq!(checked_startup_len(10_000, &l).unwrap(), 9_996);
    }

    #[tokio::test]
    async fn proxy_header_longer_than_the_cap_is_rejected() {
        let junk = vec![b'A'; 4096];
        let mut reader = BufReader::new(&junk[..]);
        assert!(read_proxy_v1_header(&mut reader, 108).await.is_err());
    }

    #[tokio::test]
    async fn well_formed_proxy_header_yields_the_client_address() {
        let line = b"PROXY TCP4 203.0.113.7 10.0.0.1 5555 5433\r\n";
        let mut reader = BufReader::new(&line[..]);
        assert_eq!(
            read_proxy_v1_header(&mut reader, 108).await.unwrap(),
            "203.0.113.7"
        );
    }

    #[tokio::test]
    async fn non_proxy_traffic_is_rejected() {
        let line = b"GET / HTTP/1.1\r\n";
        let mut reader = BufReader::new(&line[..]);
        assert!(read_proxy_v1_header(&mut reader, 108).await.is_err());
    }
}

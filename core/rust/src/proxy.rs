//! Per-connection handling: PROXY header, startup negotiation, forwarding.

use std::error::Error;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_native_tls::TlsAcceptor;

use crate::guardian::{Action, ConnectionContext, Guardian};
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

pub async fn handle_client(
    client_socket: TcpStream,
    pg_addr: String,
    guardian: Arc<Guardian>,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
    trusted: Arc<TrustedProxies>,
) -> Result<(), Box<dyn Error + Send + Sync>> {

    // 0. Is this peer allowed to speak the PROXY protocol to us?
    //
    // The header is an unauthenticated assertion. It is only meaningful from a
    // load balancer we operate, so the check happens here, before a single byte
    // of the header is parsed. Anything else is refused without reading: the
    // listener exists solely to receive HAProxy's send-proxy traffic, and a
    // connection from elsewhere is a misconfiguration or an attempt to forge a
    // source address.
    let peer_ip = client_socket.peer_addr()?.ip();
    if !trusted.is_trusted(peer_ip) {
        if let Some(suppressed) = UNTRUSTED_PEER_LOG.should_log() {
            if suppressed > 0 {
                log::warn!(
                    "Refused connection from {}: not in TRUSTED_PROXIES ({}). \
                     {} further rejections suppressed.",
                    peer_ip,
                    trusted.spec(),
                    suppressed
                );
            } else {
                log::warn!(
                    "Refused connection from {}: not in TRUSTED_PROXIES ({}). \
                     Only load balancers listed there may send a PROXY header; \
                     clients must not connect to this port directly.",
                    peer_ip,
                    trusted.spec()
                );
            }
        }
        return Ok(());
    }

    // 1. HAProxy PROXY Protocol Header Okuma
    let mut buf_reader = BufReader::new(client_socket);
    let mut proxy_header = Vec::new();
    buf_reader.read_until(b'\n', &mut proxy_header).await?;

    let header_str = String::from_utf8_lossy(&proxy_header);
    if !header_str.starts_with("PROXY") {
        log::warn!("Invalid PROXY header");
        return Ok(());
    }

    let mut parts = header_str.trim().split(' ');
    let client_ip = parts.nth(2).unwrap_or("").to_string();
    if client_ip.is_empty() {
        log::warn!("Invalid PROXY header format");
        return Ok(());
    }
    log::info!("Real Client IP: {}", client_ip);

    // 2. SSL / Plaintext Negotiation
    let mut client_stream: Box<dyn AsyncReadWrite + Unpin + Send>;
    let mut len_bytes = [0u8; 4];
    let mut payload = Vec::new();

    loop {
        buf_reader.read_exact(&mut len_bytes).await?;
        let msg_len = u32::from_be_bytes(len_bytes);
        let payload_len = (msg_len.saturating_sub(4)) as usize;
        payload.resize(payload_len, 0);
        buf_reader.read_exact(&mut payload).await?;

        if payload.len() >= 4 {
            let protocol = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);

            match protocol {
                SSL_REQUEST => {
                    if let Some(ref acceptor) = tls_acceptor {
                        log::info!("SSLRequest received. Starting TLS handshake...");
                        let raw_socket = buf_reader.into_inner();
                        let mut raw_socket = raw_socket;
                        raw_socket.write_all(b"S").await?;
                        raw_socket.flush().await?;

                        let tls_stream = acceptor.accept(raw_socket).await?;
                        log::info!("TLS connection successfully established.");
                        client_stream = Box::new(tls_stream);

                        // Read Startup Message inside TLS session
                        let mut tls_reader = BufReader::new(client_stream);
                        tls_reader.read_exact(&mut len_bytes).await?;
                        let msg_len = u32::from_be_bytes(len_bytes);
                        let payload_len = (msg_len.saturating_sub(4)) as usize;
                        payload.resize(payload_len, 0);
                        tls_reader.read_exact(&mut payload).await?;

                        client_stream = tls_reader.into_inner();
                        break;
                    } else {
                        log::info!("SSLRequest received but SSL is disabled. Forcing plaintext...");
                        let raw_socket = buf_reader.into_inner();
                        let mut raw_socket = raw_socket;
                        raw_socket.write_all(b"N").await?;
                        raw_socket.flush().await?;
                        buf_reader = BufReader::new(raw_socket);
                        continue;
                    }
                }
                GSSENC_REQUEST => {
                    log::info!("GSSENCRequest denied.");
                    let raw_socket = buf_reader.into_inner();
                    let mut raw_socket = raw_socket;
                    raw_socket.write_all(b"N").await?;
                    raw_socket.flush().await?;
                    buf_reader = BufReader::new(raw_socket);
                    continue;
                }
                _ => {
                    // Plaintext Startup Message already read
                    let raw_socket = buf_reader.into_inner();
                    client_stream = Box::new(raw_socket);
                    break;
                }
            }
        } else {
            let raw_socket = buf_reader.into_inner();
            client_stream = Box::new(raw_socket);
            break;
        }
    }

    // 3. Process Startup Message
    let mut guardian_context = ConnectionContext {
        action: Action::INSPECT,
        block_queries: vec![],
        block_tables: vec![]
    };
    let mut context_initialized = false;

    if payload.len() >= 4 {
        let protocol = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        if protocol == STARTUP_MESSAGE {
            let (user, db) = extract_user_db(&payload);
            log::info!("Startup: User='{}', DB='{}'", user, db);

            // GUARDIAN STAGE 1: Connection Check
            guardian_context = guardian.check_connection(&client_ip, &user, &db);

            if guardian_context.action == Action::DENY {
                log::warn!("Guardian: Connection denied for {} (User: {}, DB: {})", client_ip, user, db);
                let err_packet = make_error_response(
                    &format!("Connection denied by PG-Prism Guardian for IP: {}", client_ip),
                    "28000"
                );
                client_stream.write_all(&err_packet).await?;
                client_stream.flush().await?;
                return Ok(());
            }
            context_initialized = true;
        }
    }

    // 4. Connect to upstream PostgreSQL database
    let pg_socket = TcpStream::connect(pg_addr).await?;
    if let Err(e) = pg_socket.set_nodelay(true) {
        log::warn!("Failed to set TCP_NODELAY on pg socket: {}", e);
    }
    let (mut pg_read_half, mut pg_write_half) = pg_socket.into_split();

    // 5. Send modified Startup Message to Postgres
    log::info!("Startup Message captured. Injecting IP...");
    let new_payload = inject_ip_startup(&payload, &client_ip);
    let new_len = (new_payload.len() + 4) as u32;
    pg_write_half.write_all(&new_len.to_be_bytes()).await?;
    pg_write_half.write_all(&new_payload).await?;
    pg_write_half.flush().await?;

    // 6. Split client stream
    let (client_read_half, client_write_half) = tokio::io::split(client_stream);
    let mut client_reader = BufReader::with_capacity(8192, client_read_half);
    let client_write_half = Arc::new(tokio::sync::Mutex::new(client_write_half));

    // 7. Bidirectional Forwarding
    let client_ip_clone = client_ip.clone();

    // Client to Server
    let client_write_half_clone = client_write_half.clone();
    let client_to_server = async move {
        let mut transfer_buf = vec![0u8; 8192];
        let mut query_buf = Vec::with_capacity(1024);

        loop {
            let msg_type = match client_reader.read_u8().await {
                Ok(t) => t,
                Err(_) => break,
            };

            let mut len_bytes = [0u8; 4];
            if client_reader.read_exact(&mut len_bytes).await.is_err() { break; }
            let msg_len = u32::from_be_bytes(len_bytes);
            let payload_len = (msg_len.saturating_sub(4)) as usize;

            if (msg_type == b'Q' || msg_type == b'P') && payload_len < 1024 {
                query_buf.resize(payload_len, 0);
                if client_reader.read_exact(&mut query_buf).await.is_err() { break; }

                // GUARDIAN STAGE 2: Query Check
                if context_initialized {
                     if !Guardian::check_query(&query_buf, &guardian_context) {
                          log::warn!("Guardian: Query blocked.");
                          let err_packet = make_error_response("Query blocked by PG-Prism Guardian", "42501");
                          let mut guard = client_write_half_clone.lock().await;
                          if guard.write_all(&err_packet).await.is_ok() {
                              let _ = guard.write_all(b"Z\x00\x00\x00\x05I").await;
                              let _ = guard.flush().await;
                          }
                          continue; // keep connection open
                     }
                }

                let (modified, new_payload) = if msg_type == b'Q' {
                    process_simple_query(&query_buf, &client_ip_clone)
                } else {
                    process_extended_query(&query_buf, &client_ip_clone)
                };

                if modified {
                    let new_len = (new_payload.len() + 4) as u32;
                    if pg_write_half.write_u8(msg_type).await.is_err() { break; }
                    if pg_write_half.write_all(&new_len.to_be_bytes()).await.is_err() { break; }
                    if pg_write_half.write_all(&new_payload).await.is_err() { break; }
                } else {
                    if pg_write_half.write_u8(msg_type).await.is_err() { break; }
                    if pg_write_half.write_all(&len_bytes).await.is_err() { break; }
                    if pg_write_half.write_all(&query_buf).await.is_err() { break; }
                }
            } else {
                // Blind Forwarding
                if pg_write_half.write_u8(msg_type).await.is_err() { break; }
                if pg_write_half.write_all(&len_bytes).await.is_err() { break; }

                let mut left = payload_len;
                while left > 0 {
                    let chunk_len = std::cmp::min(left, transfer_buf.len());
                    if client_reader.read_exact(&mut transfer_buf[..chunk_len]).await.is_err() { break; }
                    if pg_write_half.write_all(&transfer_buf[..chunk_len]).await.is_err() { break; }
                    left -= chunk_len;
                }
            }
            let _ = pg_write_half.flush().await;
        }
        Ok::<(), Box<dyn Error + Send + Sync>>(())
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
            if guard.write_all(&buf[..n]).await.is_err() { break; }
            let _ = guard.flush().await;
        }
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    };

    let _ = tokio::try_join!(client_to_server, server_to_client);
    Ok(())
}

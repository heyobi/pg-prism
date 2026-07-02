use std::env;
use std::error::Error;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use native_tls::Identity;
use tokio_native_tls::TlsAcceptor;

// Constants
const SSL_REQUEST: u32 = 80877103;
const GSSENC_REQUEST: u32 = 80877104;
const STARTUP_MESSAGE: u32 = 196608;

mod guardian;
use guardian::{Guardian, Action, ConnectionContext};

// Trait alias for dynamic read/write stream (used for plain TcpStream and TlsStream)
trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

fn ensure_ssl_certificates() -> Result<(), Box<dyn Error + Send + Sync>> {
    use std::path::Path;
    use std::process::Command;

    let cert_path = "server.crt";
    let key_path = "server.key";
    let p12_path = "identity.p12";

    if !Path::new(p12_path).exists() {
        log::info!("SSL PKCS12 archive not found. Generating self-signed cert and p12...");
        
        // 1. Generate key and crt
        let status = Command::new("openssl")
            .args(&[
                "req", "-new", "-newkey", "rsa:2048", "-days", "365",
                "-nodes", "-x509", "-keyout", key_path, "-out", cert_path,
                "-subj", "/CN=localhost"
            ])
            .status()?;
        if !status.success() {
            return Err("Failed to generate private key and certificate using openssl".into());
        }

        // 2. Export to pkcs12 format
        let status = Command::new("openssl")
            .args(&[
                "pkcs12", "-export", "-out", p12_path,
                "-inkey", key_path, "-in", cert_path,
                "-passout", "pass:mypassword"
            ])
            .status()?;
        if !status.success() {
            return Err("Failed to export pkcs12 archive".into());
        }
        log::info!("SSL PKCS12 archive generated successfully.");
    }
    Ok(())
}

fn load_tls_acceptor() -> Result<TlsAcceptor, Box<dyn Error + Send + Sync>> {
    ensure_ssl_certificates()?;
    let p12_bytes = std::fs::read("identity.p12")?;
    let identity = Identity::from_pkcs12(&p12_bytes, "mypassword")?;
    let native_acceptor = native_tls::TlsAcceptor::builder(identity).build()?;
    Ok(TlsAcceptor::from(native_acceptor))
}

fn make_error_response(message: &str, code: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(b'S');
    body.extend_from_slice(b"ERROR\0");
    body.push(b'C');
    body.extend_from_slice(code.as_bytes());
    body.push(0);
    body.push(b'M');
    body.extend_from_slice(message.as_bytes());
    body.push(0);
    body.push(0); // terminate
    
    let length = (body.len() + 4) as u32;
    let mut packet = Vec::new();
    packet.push(b'E');
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(&body);
    packet
}

fn format_application_name(original_name: &str, app_ip: &str) -> String {
    let suffix = format!(" - {}", app_ip);
    let max_len = 63;
    if original_name.len() + suffix.len() <= max_len {
        return format!("{}{}", original_name, suffix);
    }
    let available_len = max_len.saturating_sub(suffix.len());
    if available_len == 0 {
        return suffix[..max_len].to_string();
    }
    let truncated_name = if original_name.len() > available_len {
        &original_name[..available_len]
    } else {
        original_name
    };
    format!("{}{}", truncated_name, suffix)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    // Initialize Guardian
    let guardian = Arc::new(Guardian::new("guardian.yaml").unwrap_or_else(|| {
        log::warn!("Guardian failed to load, proceeding with empty rules (Allow All)");
        Guardian { rules: vec![] }
    }));

    let ssl_enabled = env::var("SSL_ENABLED").unwrap_or_else(|_| "true".to_string()).to_lowercase() == "true";
    let tls_acceptor = if ssl_enabled {
        match load_tls_acceptor() {
            Ok(acc) => {
                log::info!("SSL/TLS termination support is active.");
                Some(Arc::new(acc))
            }
            Err(e) => {
                log::error!("Failed to initialize SSL. Disabling SSL support: {}", e);
                None
            }
        }
    } else {
        log::info!("SSL termination is disabled.");
        None
    };

    let listen_host = env::var("LISTEN_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let listen_port = env::var("LISTEN_PORT").unwrap_or_else(|_| "5433".to_string());
    let addr = format!("{}:{}", listen_host, listen_port);

    let listener = TcpListener::bind(&addr).await?;
    log::info!("PG-Prism (Ultra-Optimized Rust Core) running on {}", addr);

    let pg_host = env::var("PG_HOST").unwrap_or_else(|_| "localhost".to_string());
    let pg_port = env::var("PG_PORT").unwrap_or_else(|_| "5432".to_string());
    let pg_addr = format!("{}:{}", pg_host, pg_port);
    log::info!("Redirecting traffic to {}", pg_addr);

    loop {
        let (client_socket, _) = listener.accept().await?;
        if let Err(e) = client_socket.set_nodelay(true) {
            log::warn!("Failed to set TCP_NODELAY on client socket: {}", e);
        }
        let pg_addr = pg_addr.clone();
        let guardian = guardian.clone();
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_client(client_socket, pg_addr, guardian, tls_acceptor).await {
                log::error!("Connection dropped: {}", e);
            }
        });
    }
}

async fn handle_client(
    client_socket: TcpStream, 
    pg_addr: String, 
    guardian: Arc<Guardian>,
    tls_acceptor: Option<Arc<TlsAcceptor>>
) -> Result<(), Box<dyn Error + Send + Sync>> {
    
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

// =========================================================================
// YARDIMCI VE OPTİMİZASYON FONKSİYONLARI (BYTE-LEVEL PROCESSING)
// =========================================================================

fn contains_ignore_case_ascii(haystack: &[u8], needle: &[u8]) -> bool {
    if haystack.len() < needle.len() { return false; }
    haystack.windows(needle.len()).any(|window| window.eq_ignore_ascii_case(needle))
}

fn contains_ascii(haystack: &[u8], needle: &[u8]) -> bool {
    if haystack.len() < needle.len() { return false; }
    haystack.windows(needle.len()).any(|window| window == needle)
}

fn inject_ip_startup(payload: &[u8], ip: &str) -> Vec<u8> {
    let mut new_payload = Vec::new();
    new_payload.extend_from_slice(&payload[0..4]); 
    
    let mut params_section = &payload[4..];
    if let Some((last, rest)) = params_section.split_last() {
         if *last == 0 { params_section = rest; }
    }

    let parts: Vec<&[u8]> = params_section.split(|&b| b == 0).collect();
    let mut i = 0;
    let mut found_app_name = false;
    
    while i < parts.len() {
        if i + 1 >= parts.len() { break; }
        let key = String::from_utf8_lossy(parts[i]);
        let val = String::from_utf8_lossy(parts[i+1]);
        
        if key.is_empty() { i += 2; continue; }

        new_payload.extend_from_slice(parts[i]);
        new_payload.push(0);

        if key == "application_name" {
            found_app_name = true;
            let new_val = format_application_name(&val, ip);
            new_payload.extend_from_slice(new_val.as_bytes());
        } else {
            new_payload.extend_from_slice(parts[i+1]);
        }
        new_payload.push(0);
        i += 2;
    }

    if !found_app_name {
        new_payload.extend_from_slice(b"application_name");
        new_payload.push(0);
        let new_val = format_application_name("", ip);
        new_payload.extend_from_slice(new_val.trim_start_matches(" -").as_bytes());
        new_payload.push(0);
    }
    
    new_payload.push(0);
    new_payload
}

// OPTİMİZASYON: String dönüşümleri ve .replace() kaldırıldı. Tamamen Byte Slice üzerinden çalışıyor.
// GÜVENLİK YAMASI: Tırnak işaretlerini sadece "application_name" kelimesinden sonra arar.
fn process_simple_query(payload: &[u8], ip: &str) -> (bool, Vec<u8>) {
    if !contains_ignore_case_ascii(payload, b"set") {
        return (false, Vec::new());
    }

    let app_name_bytes = b"application_name";
    
    if let Some(app_name_pos) = payload.windows(app_name_bytes.len())
                                       .position(|w| w.eq_ignore_ascii_case(app_name_bytes)) {
        
        let search_area = &payload[app_name_pos..];

        if let Some(first_quote_offset) = search_area.iter().position(|&b| b == b'\'') {
            if let Some(second_quote_offset) = search_area[first_quote_offset + 1..].iter().position(|&b| b == b'\'') {
                
                let absolute_first_quote = app_name_pos + first_quote_offset;
                let absolute_second_quote = absolute_first_quote + 1 + second_quote_offset;
                
                let value_inside = &payload[absolute_first_quote + 1..absolute_second_quote];
                let ip_bytes = ip.as_bytes();

                if !contains_ascii(value_inside, ip_bytes) {
                    let old_val_str = String::from_utf8_lossy(value_inside);
                    let new_val_str = format_application_name(&old_val_str, ip);

                    let mut new_payload = Vec::with_capacity(payload.len() + new_val_str.len());
                    new_payload.extend_from_slice(&payload[..absolute_first_quote + 1]);
                    new_payload.extend_from_slice(new_val_str.as_bytes());
                    new_payload.extend_from_slice(&payload[absolute_second_quote..]);

                    return (true, new_payload);
                }
            }
        }
    }
    (false, Vec::new())
}

// OPTİMİZASYON: String dönüşümleri ve .replace() kaldırıldı. Tamamen Byte Slice üzerinden çalışıyor.
// GÜVENLİK YAMASI: Extended query için de tırnaklar "application_name" sonrasında aranıyor.
fn process_extended_query(payload: &[u8], ip: &str) -> (bool, Vec<u8>) {
    if let Some(idx1) = payload.iter().position(|&b| b == 0) {
        if let Some(offset2) = payload[idx1 + 1..].iter().position(|&b| b == 0) {
            let idx2 = idx1 + 1 + offset2;
            let query_bytes = &payload[idx1 + 1..idx2];
            
            if !contains_ignore_case_ascii(query_bytes, b"set") {
                return (false, Vec::new());
            }

            let app_name_bytes = b"application_name";
            if let Some(app_name_pos) = query_bytes.windows(app_name_bytes.len())
                                                   .position(|w| w.eq_ignore_ascii_case(app_name_bytes)) {
                let search_area = &query_bytes[app_name_pos..];
                if let Some(first_quote_offset) = search_area.iter().position(|&b| b == b'\'') {
                    if let Some(second_quote_offset) = search_area[first_quote_offset + 1..].iter().position(|&b| b == b'\'') {
                        let absolute_first_quote = app_name_pos + first_quote_offset;
                        let absolute_second_quote = absolute_first_quote + 1 + second_quote_offset;
                        
                        let value_inside = &query_bytes[absolute_first_quote + 1..absolute_second_quote];
                        let ip_bytes = ip.as_bytes();

                        if !contains_ascii(value_inside, ip_bytes) {
                            let old_val_str = String::from_utf8_lossy(value_inside);
                            let new_val_str = format_application_name(&old_val_str, ip);

                            let mut new_query = Vec::with_capacity(query_bytes.len() + new_val_str.len());
                            new_query.extend_from_slice(&query_bytes[..absolute_first_quote + 1]);
                            new_query.extend_from_slice(new_val_str.as_bytes());
                            new_query.extend_from_slice(&query_bytes[absolute_second_quote..]);

                            let mut new_payload = Vec::with_capacity(payload.len() + new_val_str.len());
                            new_payload.extend_from_slice(&payload[..idx1 + 1]);
                            new_payload.extend_from_slice(&new_query);
                            new_payload.push(0);
                            new_payload.extend_from_slice(&payload[idx2 + 1..]);

                            return (true, new_payload);
                        }
                    }
                }
            }
        }
    }
    (false, Vec::new())
}

// Extracts (user, database) from Startup Message payload
fn extract_user_db(payload: &[u8]) -> (String, String) {
    let mut user = String::new();
    let mut db = String::new();

    let mut params_section = &payload[4..];
    if let Some((last, rest)) = params_section.split_last() {
         if *last == 0 { params_section = rest; }
    }

    let parts: Vec<&[u8]> = params_section.split(|&b| b == 0).collect();
    let mut i = 0;
    while i < parts.len() {
        if i + 1 >= parts.len() { break; }
        let key = String::from_utf8_lossy(parts[i]);
        let val = String::from_utf8_lossy(parts[i+1]);
        
        if key == "user" {
            user = val.to_string();
        } else if key == "database" {
            db = val.to_string();
        }
        i += 2;
    }
    
    if db.is_empty() { db = user.clone(); }

    (user, db)
}

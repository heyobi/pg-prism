use std::env;
use std::error::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};

// Constants
const SSL_REQUEST: u32 = 80877103;
const GSSENC_REQUEST: u32 = 80877104;
const STARTUP_MESSAGE: u32 = 196608;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

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
        let pg_addr = pg_addr.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_client(client_socket, pg_addr).await {
                log::error!("Connection dropped: {}", e);
            }
        });
    }
}

async fn handle_client(client_socket: TcpStream, pg_addr: String) -> Result<(), Box<dyn Error>> {
    let (client_read_half, client_write_half) = client_socket.into_split();
    let mut client_reader = BufReader::with_capacity(8192, client_read_half);
    let mut client_writer = BufWriter::with_capacity(8192, client_write_half);

    // 1. HAProxy PROXY Protocol Header Okuma Optimizasyonu (Sıfır Vec Allocation)
    let mut proxy_header = Vec::new();
    client_reader.read_until(b'\n', &mut proxy_header).await?;

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

    let pg_socket = TcpStream::connect(pg_addr).await?;
    let (mut pg_read_half, pg_write_half) = pg_socket.into_split();
    // Sunucudan gelen veriyi doğrudan aktaracağımız için okuma tarafına BufReader eklememize gerek kalmadı (tokio::io::copy halledecek)
    let mut pg_writer = BufWriter::with_capacity(8192, pg_write_half);

    // 2. Startup / SSL Negotiation
    loop {
        let mut len_bytes = [0u8; 4];
        client_reader.read_exact(&mut len_bytes).await?;
        let msg_len = u32::from_be_bytes(len_bytes);
        let payload_len = (msg_len.saturating_sub(4)) as usize;

        let mut payload = vec![0u8; payload_len];
        client_reader.read_exact(&mut payload).await?;

        if payload.len() >= 4 {
            let protocol = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);

            match protocol {
                SSL_REQUEST | GSSENC_REQUEST => {
                    log::info!("SSL/GSSENC Request denied (force plaintext)");
                    client_writer.write_all(b"N").await?;
                    client_writer.flush().await?; 
                    continue;
                }
                STARTUP_MESSAGE => {
                    log::info!("Startup Message captured. Injecting IP...");
                    let new_payload = inject_ip_startup(&payload, &client_ip);
                    let new_len = (new_payload.len() + 4) as u32;
                    pg_writer.write_all(&new_len.to_be_bytes()).await?;
                    pg_writer.write_all(&new_payload).await?;
                    pg_writer.flush().await?; 
                    break;
                }
                _ => {
                    pg_writer.write_all(&len_bytes).await?;
                    pg_writer.write_all(&payload).await?;
                    pg_writer.flush().await?;
                    break;
                }
            }
        } else {
            pg_writer.write_all(&len_bytes).await?;
            pg_writer.write_all(&payload).await?;
            pg_writer.flush().await?;
            break;
        }
    }

    // 3. Çift Yönlü Asenkron Trafik (Tam Optimize)
    let client_ip_clone = client_ip.clone();
    
    // İstemciden -> Sunucuya (Client to Server)
    let client_to_server = tokio::spawn(async move {
        let mut transfer_buf = vec![0u8; 8192]; 
        let mut query_buf = Vec::with_capacity(1024); // OPTİMİZASYON: Hot Path için tekrar kullanılabilir tampon bellek

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
                // OPTİMİZASYON: Sıfırdan `vec!` yaratmak yerine mevcut buffer'ı genişletir veya daraltır.
                // Eğer kapasite (1024) yeterliyse, OS seviyesinde yeni bellek tahsisi YAPILMAZ.
                query_buf.resize(payload_len, 0); 
                if client_reader.read_exact(&mut query_buf).await.is_err() { break; }

                let (modified, new_payload) = if msg_type == b'Q' {
                    process_simple_query(&query_buf, &client_ip_clone)
                } else {
                    process_extended_query(&query_buf, &client_ip_clone)
                };

                if modified {
                    let new_len = (new_payload.len() + 4) as u32;
                    if pg_writer.write_u8(msg_type).await.is_err() { break; }
                    if pg_writer.write_all(&new_len.to_be_bytes()).await.is_err() { break; }
                    if pg_writer.write_all(&new_payload).await.is_err() { break; }
                } else {
                    if pg_writer.write_u8(msg_type).await.is_err() { break; }
                    if pg_writer.write_all(&len_bytes).await.is_err() { break; }
                    if pg_writer.write_all(&query_buf).await.is_err() { break; }
                }
            } else {
                // Blind Forwarding
                if pg_writer.write_u8(msg_type).await.is_err() { break; }
                if pg_writer.write_all(&len_bytes).await.is_err() { break; }
                
                let mut left = payload_len;
                while left > 0 {
                    let chunk_len = std::cmp::min(left, transfer_buf.len());
                    if client_reader.read_exact(&mut transfer_buf[..chunk_len]).await.is_err() { break; }
                    if pg_writer.write_all(&transfer_buf[..chunk_len]).await.is_err() { break; }
                    left -= chunk_len;
                }
            }
            let _ = pg_writer.flush().await; 
        }
    });

    // Sunucudan -> İstemciye (Server to Client)
    let server_to_client = tokio::spawn(async move {
        // OPTİMİZASYON: Manuel döngü yerine tokio'nun ultra optimize I/O copy mekanizması kullanıldı.
        // Bu, okuma ve yazma işlemlerini sistem çağrıları (syscalls) bazında en aza indirir.
        let _ = tokio::io::copy(&mut pg_read_half, &mut client_writer).await;
        let _ = client_writer.flush().await;
    });

    let _ = tokio::join!(client_to_server, server_to_client);

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
            let new_val = format!("{} - {}", val, ip);
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
        new_payload.extend_from_slice(ip.as_bytes());
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
    
    // Hem kelimenin varlığını kontrol ediyor hem de konumunu alıyoruz
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
                    let ip_suffix = format!(" - {}", ip);
                    let ip_suffix_bytes = ip_suffix.as_bytes();

                    // Sadece gerekli boyutta tek bir Vector tahsis et ve parçaları birleştir
                    let mut new_payload = Vec::with_capacity(payload.len() + ip_suffix_bytes.len());
                    new_payload.extend_from_slice(&payload[..absolute_second_quote]);
                    new_payload.extend_from_slice(ip_suffix_bytes);
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
    if !contains_ignore_case_ascii(payload, b"set") {
        return (false, Vec::new());
    }

    if let Some(idx1) = payload.iter().position(|&b| b == 0) {
        let stmt_name_with_null = &payload[..=idx1]; 
        let rest_after_stmt = &payload[idx1 + 1..];

        if let Some(idx2) = rest_after_stmt.iter().position(|&b| b == 0) {
            let query_bytes = &rest_after_stmt[..idx2];
            let rest_of_payload = &rest_after_stmt[idx2..]; 
            
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
                            let ip_suffix = format!(" - {}", ip);
                            let ip_suffix_bytes = ip_suffix.as_bytes();

                            let mut new_payload = Vec::with_capacity(payload.len() + ip_suffix_bytes.len());
                            new_payload.extend_from_slice(stmt_name_with_null);
                            new_payload.extend_from_slice(&query_bytes[..absolute_second_quote]);
                            new_payload.extend_from_slice(ip_suffix_bytes);
                            new_payload.extend_from_slice(&query_bytes[absolute_second_quote..]);
                            new_payload.extend_from_slice(rest_of_payload);

                            return (true, new_payload);
                        }
                    }
                }
            }
        }
    }
    (false, Vec::new())
}

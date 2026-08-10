//! PostgreSQL frontend/backend protocol helpers.
//!
//! Everything in this module is a pure function over bytes, which is what makes
//! it testable without a socket.

// Startup-phase protocol codes, big-endian u32 in the first four payload bytes.
pub const SSL_REQUEST: u32 = 80877103;
pub const GSSENC_REQUEST: u32 = 80877104;
pub const STARTUP_MESSAGE: u32 = 196608;

pub fn make_error_response(message: &str, code: &str) -> Vec<u8> {
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

/// PostgreSQL's NAMEDATALEN limit for `application_name`, in **bytes**.
pub const NAMEDATALEN_LIMIT: usize = 63;

/// Truncates to at most `max_bytes`, stepping back to the nearest character
/// boundary.
///
/// The limit is a byte count but `&str[..n]` panics unless `n` lands on a
/// character boundary, so a byte limit and a UTF-8 string cannot be combined
/// naively. Stepping back can drop at most three bytes.
fn truncate_on_char_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

pub fn format_application_name(original_name: &str, app_ip: &str) -> String {
    let suffix = format!(" - {}", app_ip);

    if original_name.len() + suffix.len() <= NAMEDATALEN_LIMIT {
        return format!("{}{}", original_name, suffix);
    }

    // Unreachable with real addresses: the longest IPv6 literal is 45
    // characters, so the suffix tops out at 48 bytes. The guard costs nothing
    // and the alternative, if the address source ever changes, is a panic.
    if suffix.len() >= NAMEDATALEN_LIMIT {
        return truncate_on_char_boundary(&suffix, NAMEDATALEN_LIMIT).to_string();
    }

    let available = NAMEDATALEN_LIMIT - suffix.len();
    let truncated = truncate_on_char_boundary(original_name, available);
    format!("{}{}", truncated, suffix)
}

pub fn inject_ip_startup(payload: &[u8], ip: &str) -> Vec<u8> {
    // A startup payload opens with a four-byte protocol version. Anything
    // shorter is not one, so forward it untouched rather than indexing past the
    // end. Callers reject short packets before reaching here; this guard exists
    // so the function cannot panic no matter who calls it.
    if payload.len() < 4 {
        return payload.to_vec();
    }

    let mut new_payload = Vec::new();
    new_payload.extend_from_slice(&payload[0..4]);

    let mut params_section = &payload[4..];
    if let Some((last, rest)) = params_section.split_last() {
        if *last == 0 {
            params_section = rest;
        }
    }

    let parts: Vec<&[u8]> = params_section.split(|&b| b == 0).collect();
    let mut i = 0;
    let mut found_app_name = false;

    while i < parts.len() {
        if i + 1 >= parts.len() {
            break;
        }
        let key = String::from_utf8_lossy(parts[i]);
        let val = String::from_utf8_lossy(parts[i + 1]);

        if key.is_empty() {
            i += 2;
            continue;
        }

        new_payload.extend_from_slice(parts[i]);
        new_payload.push(0);

        if key == "application_name" {
            found_app_name = true;
            let new_val = format_application_name(&val, ip);
            new_payload.extend_from_slice(new_val.as_bytes());
        } else {
            new_payload.extend_from_slice(parts[i + 1]);
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

pub fn extract_user_db(payload: &[u8]) -> (String, String) {
    let mut user = String::new();
    let mut db = String::new();

    if payload.len() < 4 {
        return (user, db);
    }

    let mut params_section = &payload[4..];
    if let Some((last, rest)) = params_section.split_last() {
        if *last == 0 {
            params_section = rest;
        }
    }

    let parts: Vec<&[u8]> = params_section.split(|&b| b == 0).collect();
    let mut i = 0;
    while i < parts.len() {
        if i + 1 >= parts.len() {
            break;
        }
        let key = String::from_utf8_lossy(parts[i]);
        let val = String::from_utf8_lossy(parts[i + 1]);

        if key == "user" {
            user = val.to_string();
        } else if key == "database" {
            db = val.to_string();
        }
        i += 2;
    }

    if db.is_empty() {
        db = user.clone();
    }

    (user, db)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- format_application_name -------------------------------------------

    /// AUDIT.md finding #4. NAMEDATALEN is a byte limit, `&str[..n]` is a byte
    /// index, and slicing a multi-byte character in half panics. Sweeping the
    /// suffix length moves the cut across every possible alignment.
    #[test]
    fn truncation_never_panics_regardless_of_boundary_alignment() {
        for ch in ["é", "ğ", "→", "🔥"] {
            let name = ch.repeat(60);
            for ip_len in 7..=45 {
                let ip = "1".repeat(ip_len);
                let out = format_application_name(&name, &ip);
                assert!(
                    out.len() <= 63,
                    "{:?} + {}-byte ip produced {} bytes",
                    ch,
                    ip_len,
                    out.len()
                );
            }
        }
    }

    #[test]
    fn output_never_exceeds_the_namedatalen_limit() {
        for name_len in 0..200 {
            let name = "a".repeat(name_len);
            let out = format_application_name(&name, "192.168.100.200");
            assert!(
                out.len() <= 63,
                "{} bytes for name_len {}",
                out.len(),
                name_len
            );
        }
    }

    #[test]
    fn short_names_keep_the_whole_suffix() {
        assert_eq!(
            format_application_name("DBeaver", "192.168.1.50"),
            "DBeaver - 192.168.1.50"
        );
    }

    #[test]
    fn ascii_truncation_keeps_the_ip_intact() {
        let out = format_application_name(&"x".repeat(200), "10.0.0.1");
        assert!(out.ends_with(" - 10.0.0.1"), "got {:?}", out);
        assert_eq!(out.len(), 63);
    }

    #[test]
    fn multibyte_truncation_keeps_the_ip_intact() {
        let out = format_application_name(&"→".repeat(60), "10.0.0.1");
        assert!(out.ends_with(" - 10.0.0.1"), "got {:?}", out);
    }

    // ---- inject_ip_startup --------------------------------------------------

    /// AUDIT.md finding #5. A four-byte startup packet yields an empty payload
    /// and `&payload[0..4]` panics. Unauthenticated, pre-handshake.
    #[test]
    fn injection_does_not_panic_on_empty_payload() {
        let _ = inject_ip_startup(&[], "10.0.0.1");
    }

    #[test]
    fn injection_does_not_panic_on_short_payloads() {
        for n in 0..4 {
            let payload = vec![0u8; n];
            let _ = inject_ip_startup(&payload, "10.0.0.1");
        }
    }

    /// A CancelRequest body is 12 bytes of binary, not key/value pairs.
    #[test]
    fn injection_does_not_panic_on_cancel_request_shaped_input() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&80877102u32.to_be_bytes());
        payload.extend_from_slice(&4242u32.to_be_bytes());
        payload.extend_from_slice(&0xdeadbeefu32.to_be_bytes());
        let _ = inject_ip_startup(&payload, "10.0.0.1");
    }

    #[test]
    fn injection_rewrites_an_existing_application_name() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&STARTUP_MESSAGE.to_be_bytes());
        payload.extend_from_slice(b"user\0postgres\0application_name\0psql\0\0");
        let out = inject_ip_startup(&payload, "10.0.0.1");
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("psql - 10.0.0.1"), "got {:?}", text);
    }

    // ---- extract_user_db ----------------------------------------------------

    #[test]
    fn extract_does_not_panic_on_short_payloads() {
        for n in 0..4 {
            let payload = vec![0u8; n];
            let _ = extract_user_db(&payload);
        }
    }

    #[test]
    fn extract_reads_user_and_database() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&STARTUP_MESSAGE.to_be_bytes());
        payload.extend_from_slice(b"user\0alice\0database\0shop\0\0");
        assert_eq!(
            extract_user_db(&payload),
            ("alice".to_string(), "shop".to_string())
        );
    }

    #[test]
    fn extract_defaults_database_to_user() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&STARTUP_MESSAGE.to_be_bytes());
        payload.extend_from_slice(b"user\0alice\0\0");
        assert_eq!(
            extract_user_db(&payload),
            ("alice".to_string(), "alice".to_string())
        );
    }
}

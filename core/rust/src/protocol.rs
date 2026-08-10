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

pub fn format_application_name(original_name: &str, app_ip: &str) -> String {
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

pub fn contains_ignore_case_ascii(haystack: &[u8], needle: &[u8]) -> bool {
    if haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

pub fn contains_ascii(haystack: &[u8], needle: &[u8]) -> bool {
    if haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|window| window == needle)
}

pub fn inject_ip_startup(payload: &[u8], ip: &str) -> Vec<u8> {
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

pub fn process_simple_query(payload: &[u8], ip: &str) -> (bool, Vec<u8>) {
    if !contains_ignore_case_ascii(payload, b"set") {
        return (false, Vec::new());
    }

    let app_name_bytes = b"application_name";

    if let Some(app_name_pos) = payload
        .windows(app_name_bytes.len())
        .position(|w| w.eq_ignore_ascii_case(app_name_bytes))
    {
        let search_area = &payload[app_name_pos..];

        if let Some(first_quote_offset) = search_area.iter().position(|&b| b == b'\'') {
            if let Some(second_quote_offset) = search_area[first_quote_offset + 1..]
                .iter()
                .position(|&b| b == b'\'')
            {
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

pub fn process_extended_query(payload: &[u8], ip: &str) -> (bool, Vec<u8>) {
    if let Some(idx1) = payload.iter().position(|&b| b == 0) {
        if let Some(offset2) = payload[idx1 + 1..].iter().position(|&b| b == 0) {
            let idx2 = idx1 + 1 + offset2;
            let query_bytes = &payload[idx1 + 1..idx2];

            if !contains_ignore_case_ascii(query_bytes, b"set") {
                return (false, Vec::new());
            }

            let app_name_bytes = b"application_name";
            if let Some(app_name_pos) = query_bytes
                .windows(app_name_bytes.len())
                .position(|w| w.eq_ignore_ascii_case(app_name_bytes))
            {
                let search_area = &query_bytes[app_name_pos..];
                if let Some(first_quote_offset) = search_area.iter().position(|&b| b == b'\'') {
                    if let Some(second_quote_offset) = search_area[first_quote_offset + 1..]
                        .iter()
                        .position(|&b| b == b'\'')
                    {
                        let absolute_first_quote = app_name_pos + first_quote_offset;
                        let absolute_second_quote = absolute_first_quote + 1 + second_quote_offset;

                        let value_inside =
                            &query_bytes[absolute_first_quote + 1..absolute_second_quote];
                        let ip_bytes = ip.as_bytes();

                        if !contains_ascii(value_inside, ip_bytes) {
                            let old_val_str = String::from_utf8_lossy(value_inside);
                            let new_val_str = format_application_name(&old_val_str, ip);

                            let mut new_query =
                                Vec::with_capacity(query_bytes.len() + new_val_str.len());
                            new_query.extend_from_slice(&query_bytes[..absolute_first_quote + 1]);
                            new_query.extend_from_slice(new_val_str.as_bytes());
                            new_query.extend_from_slice(&query_bytes[absolute_second_quote..]);

                            let mut new_payload =
                                Vec::with_capacity(payload.len() + new_val_str.len());
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

/// Extracts (user, database) from a StartupMessage payload.
pub fn extract_user_db(payload: &[u8]) -> (String, String) {
    let mut user = String::new();
    let mut db = String::new();

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

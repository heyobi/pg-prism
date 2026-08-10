//! Bounds on anything a client controls.
//!
//! Every value here exists because the connection path previously had no limit
//! at all: lengths came off the wire and were used to size buffers, and no step
//! of the handshake could time out.

use std::time::Duration;

/// PostgreSQL's own cap on a startup packet (`MAX_STARTUP_PACKET_LENGTH` in
/// `src/backend/postmaster/postmaster.c`). Matching it means we reject exactly
/// what the server would.
pub const MAX_STARTUP_PACKET_LENGTH: usize = 10000;

/// The shortest meaningful startup-phase packet: a four-byte length followed by
/// a four-byte protocol code. SSLRequest and GSSENCRequest are exactly this.
pub const MIN_STARTUP_PACKET_LENGTH: usize = 8;

/// A PROXY v1 header is at most 107 bytes including CRLF, per the protocol
/// specification. One extra byte lets us detect an overlong line rather than
/// silently truncating at the limit.
pub const MAX_PROXY_V1_HEADER_LEN: usize = 108;

#[derive(Debug, Clone)]
pub struct Limits {
    /// Covers the PROXY header, SSL negotiation and the startup message
    /// together. A legitimate client completes all of it in milliseconds.
    pub handshake_timeout: Duration,
    pub upstream_connect_timeout: Duration,
    /// How long to wait for a client to react after PostgreSQL has gone and we
    /// have sent it EOF. Nothing it sends after that point can be answered, so
    /// this only bounds a client that ignores the close.
    pub drain_timeout: Duration,
    pub max_startup_len: usize,
    pub max_proxy_header_len: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            handshake_timeout: Duration::from_secs(10),
            upstream_connect_timeout: Duration::from_secs(5),
            drain_timeout: Duration::from_secs(10),
            max_startup_len: MAX_STARTUP_PACKET_LENGTH,
            max_proxy_header_len: MAX_PROXY_V1_HEADER_LEN,
        }
    }
}

impl Limits {
    /// Reads the two timeouts from the environment, in seconds. Malformed
    /// values are an error rather than a silent fallback: a timeout that
    /// quietly reverts to the default is a timeout the operator thinks they
    /// changed.
    pub fn from_env() -> Result<Self, String> {
        let mut limits = Limits::default();
        if let Ok(v) = std::env::var("HANDSHAKE_TIMEOUT_SECS") {
            limits.handshake_timeout =
                Duration::from_secs(parse_secs("HANDSHAKE_TIMEOUT_SECS", &v)?);
        }
        if let Ok(v) = std::env::var("UPSTREAM_CONNECT_TIMEOUT_SECS") {
            limits.upstream_connect_timeout =
                Duration::from_secs(parse_secs("UPSTREAM_CONNECT_TIMEOUT_SECS", &v)?);
        }
        Ok(limits)
    }
}

fn parse_secs(name: &str, raw: &str) -> Result<u64, String> {
    let n: u64 = raw
        .trim()
        .parse()
        .map_err(|_| format!("{} must be a whole number of seconds, got {:?}", name, raw))?;
    if n == 0 {
        return Err(format!("{} must be greater than zero", name));
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_bounded() {
        let l = Limits::default();
        assert_eq!(l.max_startup_len, 10000);
        assert_eq!(l.max_proxy_header_len, 108);
        assert!(l.handshake_timeout > Duration::ZERO);
        assert!(l.upstream_connect_timeout > Duration::ZERO);
    }

    #[test]
    fn zero_and_garbage_timeouts_are_rejected() {
        assert!(parse_secs("X", "0").is_err());
        assert!(parse_secs("X", "abc").is_err());
        assert!(parse_secs("X", "-1").is_err());
        assert_eq!(parse_secs("X", " 30 ").unwrap(), 30);
    }
}

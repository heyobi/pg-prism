//! Which peers are allowed to speak the PROXY protocol to us.
//!
//! The PROXY header is an assertion by the peer about who *it* is talking to. It
//! carries no authentication, so it is only meaningful when the peer itself is
//! known to be a load balancer we operate. Without that check, any client that
//! can open a TCP connection to the listener can claim any source address, which
//! both falsifies `pg_stat_activity` and defeats Guardian's `ips:` rules.
//!
//! This mirrors the shape of the `proxy_servers` GUC in the PROXY protocol patch
//! proposed for PostgreSQL core: a list of CIDRs whose members are permitted to
//! prefix a connection with a PROXY header, empty-by-default in core and
//! loopback-by-default here because PG-Prism is a sidecar.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use cidr::IpCidr;

/// Loopback only. PG-Prism is a per-host sidecar; the expected deployment has
/// HAProxy on the same machine or in the same pod.
pub const DEFAULT_TRUSTED_PROXIES: &str = "127.0.0.0/8,::1/128";

pub const ENV_VAR: &str = "TRUSTED_PROXIES";

#[derive(Debug)]
pub enum TrustError {
    Empty,
    BadEntry { entry: String },
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustError::Empty => write!(
                f,
                "{} is set but empty. An empty allowlist trusts nothing and would \
                 reject every connection. To trust every peer, which disables \
                 spoofing protection entirely, set {}=0.0.0.0/0,::/0",
                ENV_VAR, ENV_VAR
            ),
            TrustError::BadEntry { entry } => write!(
                f,
                "{} contains an entry that is not an IP address or CIDR block: {:?}",
                ENV_VAR, entry
            ),
        }
    }
}

impl std::error::Error for TrustError {}

#[derive(Debug, Clone)]
pub struct TrustedProxies {
    nets: Vec<IpCidr>,
    spec: String,
}

impl TrustedProxies {
    /// Parses a comma-separated list of CIDR blocks or bare IP addresses.
    ///
    /// Fails closed: a single malformed entry is an error rather than a skipped
    /// line, because silently dropping an entry from an allowlist changes who is
    /// trusted without saying so.
    pub fn parse(spec: &str) -> Result<Self, TrustError> {
        let entries: Vec<&str> = spec
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        if entries.is_empty() {
            return Err(TrustError::Empty);
        }

        let mut nets = Vec::with_capacity(entries.len());
        for entry in entries {
            // Accept both "10.0.0.0/8" and a bare "10.0.0.1".
            let net = IpCidr::from_str(entry)
                .or_else(|_| IpAddr::from_str(entry).map(IpCidr::new_host))
                .map_err(|_| TrustError::BadEntry {
                    entry: entry.to_string(),
                })?;
            nets.push(net);
        }

        Ok(TrustedProxies {
            nets,
            spec: spec.trim().to_string(),
        })
    }

    /// Reads the allowlist from the environment, falling back to loopback.
    pub fn from_env() -> Result<Self, TrustError> {
        match std::env::var(ENV_VAR) {
            Ok(spec) => Self::parse(&spec),
            Err(_) => Self::parse(DEFAULT_TRUSTED_PROXIES),
        }
    }

    pub fn is_trusted(&self, peer: IpAddr) -> bool {
        let normalised = normalise(peer);
        self.nets
            .iter()
            .any(|net| net.contains(&peer) || net.contains(&normalised))
    }

    pub fn spec(&self) -> &str {
        &self.spec
    }
}

/// Collapses an IPv4-mapped IPv6 address (`::ffff:10.0.0.1`) to its IPv4 form.
///
/// A listener bound to `::` receives IPv4 peers in mapped form on most
/// platforms. Matching those against an IPv4 CIDR without normalising is the
/// same class of bug as AUDIT.md finding #15, where a `0.0.0.0/0` rule silently
/// failed to match IPv6 clients.
fn normalise(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        v4 => v4,
    }
}

/// Rate-limited logging for rejected peers.
///
/// Rejections are attacker-triggerable, so logging one line per rejected
/// connection turns the allowlist into a log amplification vector. This emits at
/// most one line per interval and reports how many it swallowed.
pub struct RejectionLog {
    last: Mutex<Option<Instant>>,
    suppressed: AtomicU64,
    interval: Duration,
}

impl RejectionLog {
    pub fn new(interval: Duration) -> Self {
        RejectionLog {
            last: Mutex::new(None),
            suppressed: AtomicU64::new(0),
            interval,
        }
    }

    /// Returns the number of previously suppressed events if the caller should
    /// log now, or `None` if this event should be swallowed.
    pub fn should_log(&self) -> Option<u64> {
        let now = Instant::now();
        let mut last = match self.last.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let due = match *last {
            None => true,
            Some(t) => now.duration_since(t) >= self.interval,
        };
        if due {
            *last = Some(now);
            Some(self.suppressed.swap(0, Ordering::Relaxed))
        } else {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

impl Default for RejectionLog {
    fn default() -> Self {
        RejectionLog::new(Duration::from_secs(10))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    fn default() -> TrustedProxies {
        TrustedProxies::parse(DEFAULT_TRUSTED_PROXIES).unwrap()
    }

    #[test]
    fn default_trusts_ipv4_loopback() {
        assert!(default().is_trusted(ip("127.0.0.1")));
        assert!(default().is_trusted(ip("127.1.2.3")));
    }

    #[test]
    fn default_trusts_ipv6_loopback() {
        assert!(default().is_trusted(ip("::1")));
    }

    #[test]
    fn default_rejects_off_host_addresses() {
        assert!(!default().is_trusted(ip("10.0.0.5")));
        assert!(!default().is_trusted(ip("192.168.1.50")));
        assert!(!default().is_trusted(ip("203.0.113.99")));
        assert!(!default().is_trusted(ip("2001:db8::1")));
    }

    /// A listener on `::` sees IPv4 peers as `::ffff:a.b.c.d`. Failing to
    /// normalise would silently reject the local HAProxy.
    #[test]
    fn ipv4_mapped_loopback_is_trusted() {
        assert!(default().is_trusted(ip("::ffff:127.0.0.1")));
    }

    #[test]
    fn ipv4_mapped_off_host_address_is_still_rejected() {
        assert!(!default().is_trusted(ip("::ffff:10.0.0.5")));
    }

    #[test]
    fn parse_rejects_malformed_entries() {
        assert!(TrustedProxies::parse("127.0.0.0/8,not-an-ip").is_err());
        assert!(TrustedProxies::parse("999.0.0.1/8").is_err());
        assert!(TrustedProxies::parse("127.0.0.0/33").is_err());
    }

    #[test]
    fn parse_rejects_empty_specification() {
        assert!(matches!(TrustedProxies::parse(""), Err(TrustError::Empty)));
        assert!(matches!(
            TrustedProxies::parse("   ,  , "),
            Err(TrustError::Empty)
        ));
    }

    #[test]
    fn parse_tolerates_whitespace() {
        let t = TrustedProxies::parse(" 10.0.0.0/8 , 192.168.0.0/16 ").unwrap();
        assert!(t.is_trusted(ip("10.1.2.3")));
        assert!(t.is_trusted(ip("192.168.99.1")));
    }

    #[test]
    fn parse_accepts_bare_addresses_as_hosts() {
        let t = TrustedProxies::parse("10.0.0.7,::1").unwrap();
        assert!(t.is_trusted(ip("10.0.0.7")));
        assert!(!t.is_trusted(ip("10.0.0.8")));
        assert!(t.is_trusted(ip("::1")));
    }

    /// Documents the semantics that bit Guardian in finding #15: the IPv4
    /// default route is not a catch-all, it is a catch-all *for IPv4*.
    #[test]
    fn ipv4_default_route_does_not_cover_ipv6() {
        let t = TrustedProxies::parse("0.0.0.0/0").unwrap();
        assert!(t.is_trusted(ip("203.0.113.99")));
        assert!(!t.is_trusted(ip("2001:db8::1")));
    }

    #[test]
    fn both_default_routes_trust_everything() {
        let t = TrustedProxies::parse("0.0.0.0/0,::/0").unwrap();
        assert!(t.is_trusted(ip("203.0.113.99")));
        assert!(t.is_trusted(ip("2001:db8::1")));
    }

    #[test]
    fn rejection_log_throttles() {
        let log = RejectionLog::new(Duration::from_secs(3600));
        assert_eq!(log.should_log(), Some(0), "first event logs");
        assert_eq!(log.should_log(), None, "second is suppressed");
        assert_eq!(log.should_log(), None, "third is suppressed");
    }

    #[test]
    fn rejection_log_reports_suppressed_count() {
        let log = RejectionLog::new(Duration::from_millis(0));
        assert_eq!(log.should_log(), Some(0));
        let log = RejectionLog::new(Duration::from_secs(3600));
        log.should_log();
        log.should_log();
        log.should_log();
        // Force the interval to have elapsed by constructing a fresh window.
        let counted = log.suppressed.load(Ordering::Relaxed);
        assert_eq!(counted, 2);
    }
}

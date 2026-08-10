use chrono::{Local, Timelike};
use cidr::IpCidr;
use log::{info, warn};
use memchr::memmem;
use serde::Deserialize;
use std::fs::File;
use std::io::BufReader;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Deserialize, Clone)]
pub struct GuardianConfig {
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Rule {
    pub name: String,
    pub action: Action,
    pub ips: Option<Vec<String>>,
    pub users: Option<Vec<String>>,
    pub databases: Option<Vec<String>>,
    pub time_range: Option<String>,
    pub block_queries: Option<Vec<String>>, // e.g. ["DELETE", "DROP"]
    pub block_tables: Option<Vec<String>>,  // e.g. ["salary", "users"]
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub enum Action {
    ALLOW,   // Bypass Query Filter -> Trusted
    INSPECT, // Apply Query Filter
    DENY,    // Drop Connection
}

#[derive(Debug)]
pub struct Guardian {
    pub rules: Vec<Rule>,
}

pub struct ConnectionContext {
    pub action: Action,
    pub block_queries: Vec<Vec<u8>>,
    pub block_tables: Vec<Vec<u8>>,
}

/// Is `now`, formatted `HH:MM`, inside `range`, formatted `HH:MM-HH:MM`?
///
/// A range whose end is earlier than its start wraps around midnight. The
/// previous implementation compared strings directly, so `22:00-06:00` required
/// a time that was both after 22:00 and before 06:00 and therefore never
/// matched: an overnight maintenance window silently did nothing (finding #30).
///
/// A malformed range matches nothing, which for a rule that may carry a DENY is
/// the safer direction to fail.
fn time_in_range(now: &str, range: &str) -> bool {
    let Some((start, end)) = range.split_once('-') else {
        return false;
    };
    let (start, end) = (start.trim(), end.trim());
    if !is_hhmm(start) || !is_hhmm(end) {
        return false;
    }
    if start <= end {
        now >= start && now <= end
    } else {
        // Wraps midnight: inside if it is after the start or before the end.
        now >= start || now <= end
    }
}

fn is_hhmm(s: &str) -> bool {
    let Some((h, m)) = s.split_once(':') else {
        return false;
    };
    h.len() == 2
        && m.len() == 2
        && h.chars().all(|c| c.is_ascii_digit())
        && m.chars().all(|c| c.is_ascii_digit())
        && h.parse::<u32>().map(|v| v < 24).unwrap_or(false)
        && m.parse::<u32>().map(|v| v < 60).unwrap_or(false)
}

/// Why a ruleset could not be loaded.
#[derive(Debug)]
pub enum ConfigError {
    /// The file is present but not valid. This is fatal: a firewall that
    /// silently disables itself on a typo is worse than no firewall, because
    /// the operator believes it is running.
    Invalid { path: String, detail: String },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Invalid { path, detail } => write!(
                f,
                "Guardian config {} could not be parsed: {}. Refusing to start: \
                 continuing would silently run with no rules at all.",
                path, detail
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Guardian {
    /// Loads a ruleset.
    ///
    /// A missing file means "no rules configured", which is a legitimate way to
    /// run the proxy and yields an empty ruleset. A file that exists but does
    /// not parse is an error, not a warning: it used to degrade silently to
    /// allow-all (finding #18).
    pub fn load(config_path: &str) -> Result<Self, ConfigError> {
        let file = match File::open(config_path) {
            Ok(f) => f,
            Err(_) => {
                warn!(
                    "No Guardian config at {}. Running with no rules; every \
                     connection is inspected against an empty ruleset.",
                    config_path
                );
                return Ok(Guardian { rules: vec![] });
            }
        };
        let reader = BufReader::new(file);
        let config: GuardianConfig =
            serde_yaml::from_reader(reader).map_err(|e| ConfigError::Invalid {
                path: config_path.to_string(),
                detail: e.to_string(),
            })?;

        info!("Guardian loaded with {} rules.", config.rules.len());
        let guardian = Guardian {
            rules: config.rules,
        };
        guardian.warn_about_unreachable_rules();
        Ok(guardian)
    }

    /// Flags rules whose address list cannot match some clients.
    ///
    /// `0.0.0.0/0` is the IPv4 default route, not a catch-all: it does not
    /// match an IPv6 client, so a rule written that way silently stops applying
    /// the moment somebody connects over IPv6 (finding #15). Rather than
    /// quietly redefining CIDR semantics, say so at startup.
    fn warn_about_unreachable_rules(&self) {
        for rule in &self.rules {
            let Some(ips) = &rule.ips else { continue };
            let parsed: Vec<IpCidr> = ips.iter().filter_map(|s| s.parse().ok()).collect();
            if parsed.is_empty() {
                warn!(
                    "Guardian rule '{}' lists addresses but none of them parse as \
                     CIDR blocks; the rule can never match.",
                    rule.name
                );
                continue;
            }
            let has_v4 = parsed.iter().any(|c| matches!(c, IpCidr::V4(_)));
            let has_v6 = parsed.iter().any(|c| matches!(c, IpCidr::V6(_)));
            if has_v4 && !has_v6 {
                warn!(
                    "Guardian rule '{}' lists only IPv4 addresses, so it will not \
                     match IPv6 clients. Note that 0.0.0.0/0 is the IPv4 default \
                     route, not a catch-all: omit `ips` entirely to match any \
                     address, or add ::/0 alongside it.",
                    rule.name
                );
            } else if has_v6 && !has_v4 {
                warn!(
                    "Guardian rule '{}' lists only IPv6 addresses, so it will not \
                     match IPv4 clients.",
                    rule.name
                );
            }
        }
    }

    pub fn check_connection(&self, ip: &str, user: &str, db: &str) -> ConnectionContext {
        let ip_addr = match IpAddr::from_str(ip) {
            Ok(addr) => addr,
            Err(_) => {
                return ConnectionContext {
                    action: Action::DENY,
                    block_queries: vec![],
                    block_tables: vec![],
                };
            }
        };

        let now = Local::now();
        let current_time_str = format!("{:02}:{:02}", now.hour(), now.minute());

        for rule in &self.rules {
            // 1. IP Check
            // CIDR semantics are exact: 0.0.0.0/0 matches IPv4 and nothing
            // else. The dead `else if` that used to be here pretended
            // otherwise, and could never run anyway because "0.0.0.0/0" parses
            // successfully. Rules that cannot match every family are flagged at
            // load time instead; omitting `ips` is how you say "any address".
            if let Some(ips) = &rule.ips {
                let matched = ips.iter().any(|cidr_str| {
                    cidr_str
                        .parse::<IpCidr>()
                        .map(|cidr| cidr.contains(&ip_addr))
                        .unwrap_or(false)
                });
                if !matched {
                    continue;
                }
            }

            // 2. User Check
            if let Some(users) = &rule.users {
                if !users.contains(&user.to_string()) {
                    continue;
                }
            }

            // 3. Database Check
            if let Some(dbs) = &rule.databases {
                if !dbs.contains(&db.to_string()) {
                    continue;
                }
            }

            // 4. Time Check
            if let Some(range) = &rule.time_range {
                if !time_in_range(&current_time_str, range) {
                    continue;
                }
            }

            info!(
                "Guardian: Connection matched rule '{}' -> {:?}",
                rule.name, rule.action
            );

            // Convert block lists to bytes for fast searching
            let block_queries = rule
                .block_queries
                .clone()
                .unwrap_or_default()
                .iter()
                .map(|s| s.to_uppercase().as_bytes().to_vec())
                .collect();

            let block_tables = rule
                .block_tables
                .clone()
                .unwrap_or_default()
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect();

            return ConnectionContext {
                action: rule.action.clone(),
                block_queries,
                block_tables,
            };
        }

        // Default: Allow if no rule matches? Or Inspect?
        // Safe default: Inspect with no specific blocks (effectively allow but generic checks if added later)
        ConnectionContext {
            action: Action::INSPECT,
            block_queries: vec![],
            block_tables: vec![],
        }
    }

    pub fn check_query(query: &[u8], context: &ConnectionContext) -> bool {
        // 1. Quick allow
        if context.action == Action::ALLOW {
            return true;
        }

        // 2. Deny check (should be caught at connection, but double check)
        if context.action == Action::DENY {
            return false;
        }

        // 3. Block Queries (Command types: DELETE, DROP etc)
        // Optimization: commands are usually at the start.
        // But users can write "   DELETE FROM..."
        // A simple verify is contains_ignore_case
        // For max performance, we assume standard SQL structure or search whole string.

        for blocked_cmd in &context.block_queries {
            if contains_ignore_case_ascii(query, blocked_cmd) {
                warn!(
                    "Guardian Blocked Query: Command '{:?}' detected.",
                    String::from_utf8_lossy(blocked_cmd)
                );
                return false;
            }
        }

        // 4. Block Tables
        for blocked_table in &context.block_tables {
            if contains_ascii(query, blocked_table) {
                warn!(
                    "Guardian Blocked Query: Table '{:?}' access detected.",
                    String::from_utf8_lossy(blocked_table)
                );
                return false;
            }
        }

        true
    }
}

// Byte-level search utils (Borrowed from main.rs, could be shared in utils.rs)
fn contains_ignore_case_ascii(haystack: &[u8], needle: &[u8]) -> bool {
    if haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn contains_ascii(haystack: &[u8], needle: &[u8]) -> bool {
    if haystack.len() < needle.len() {
        return false;
    }
    // Memchr is faster for single byte, but for substring we use memmem
    memmem::find(haystack, needle).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- time_in_range, finding #30 ----------------------------------------

    #[test]
    fn a_daytime_range_behaves_normally() {
        assert!(time_in_range("09:30", "09:00-17:00"));
        assert!(time_in_range("09:00", "09:00-17:00"), "start is inclusive");
        assert!(time_in_range("17:00", "09:00-17:00"), "end is inclusive");
        assert!(!time_in_range("08:59", "09:00-17:00"));
        assert!(!time_in_range("17:01", "09:00-17:00"));
    }

    /// The bug: string comparison required a time that was both after 22:00 and
    /// before 06:00, so an overnight maintenance window never matched.
    #[test]
    fn an_overnight_range_wraps_around_midnight() {
        for t in ["22:00", "23:59", "00:00", "03:00", "06:00"] {
            assert!(time_in_range(t, "22:00-06:00"), "{} should be inside", t);
        }
        for t in ["21:59", "06:01", "12:00"] {
            assert!(!time_in_range(t, "22:00-06:00"), "{} should be outside", t);
        }
    }

    #[test]
    fn a_malformed_range_matches_nothing() {
        for range in [
            "",
            "09:00",
            "09:00-",
            "-17:00",
            "9:00-17:00",
            "25:00-26:00",
            "09:60-10:00",
            "nine-five",
        ] {
            assert!(
                !time_in_range("12:00", range),
                "{:?} should match nothing",
                range
            );
        }
    }

    #[test]
    fn whitespace_around_a_range_is_tolerated() {
        assert!(time_in_range("12:00", " 09:00 - 17:00 "));
    }

    // ---- loading, finding #18 ----------------------------------------------

    fn temp_config(contents: &str) -> String {
        use std::io::Write;
        let mut path = std::env::temp_dir();
        path.push(format!(
            "pg-prism-guardian-test-{}-{:?}.yaml",
            std::process::id(),
            std::thread::current().id()
        ));
        let mut f = File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path.to_string_lossy().to_string()
    }

    #[test]
    fn a_missing_file_means_no_rules_and_is_not_an_error() {
        let g = Guardian::load("definitely-not-a-real-path.yaml").unwrap();
        assert!(g.rules.is_empty());
    }

    /// A firewall that disables itself on a typo is worse than no firewall,
    /// because the operator believes it is running.
    #[test]
    fn a_malformed_file_is_fatal_rather_than_allow_all() {
        let path = temp_config("rules:\n  - name: broken\n    action: NOT_AN_ACTION\n");
        let err = Guardian::load(&path).expect_err("a malformed config was accepted");
        let msg = err.to_string();
        assert!(
            msg.contains("Refusing to start"),
            "unhelpful error: {}",
            msg
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_valid_file_loads_its_rules() {
        let path = temp_config(
            "rules:\n  - name: block-drops\n    action: INSPECT\n    block_queries: [\"DROP\"]\n",
        );
        let g = Guardian::load(&path).unwrap();
        assert_eq!(g.rules.len(), 1);
        assert_eq!(g.rules[0].name, "block-drops");
        let _ = std::fs::remove_file(&path);
    }
}

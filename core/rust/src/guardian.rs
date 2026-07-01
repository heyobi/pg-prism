use std::fs::File;
use std::io::BufReader;
use std::str::FromStr;
use serde::Deserialize;
use cidr::IpCidr;
use chrono::{Local, Timelike};
use std::net::IpAddr;
use log::{info, warn, error};
use memchr::memmem;

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

pub struct Guardian {
    pub rules: Vec<Rule>,
}

pub struct ConnectionContext {
    pub action: Action,
    pub block_queries: Vec<Vec<u8>>,
    pub block_tables: Vec<Vec<u8>>,
}

impl Guardian {
    pub fn new(config_path: &str) -> Option<Self> {
        let file = match File::open(config_path) {
            Ok(f) => f,
            Err(_) => {
                warn!("Guardian Config not found at {}, defaulting to Allow All.", config_path);
                return None;
            }
        };
        let reader = BufReader::new(file);
        let config: GuardianConfig = match serde_yaml::from_reader(reader) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to parse Guardian Config: {}", e);
                return None;
            }
        };

        info!("Guardian loaded with {} rules.", config.rules.len());
        Some(Guardian { rules: config.rules })
    }

    pub fn check_connection(&self, ip: &str, user: &str, db: &str) -> ConnectionContext {
        let ip_addr = match IpAddr::from_str(ip) {
            Ok(addr) => addr,
            Err(_) => {
                return ConnectionContext { action: Action::DENY, block_queries: vec![], block_tables: vec![] };
            }
        };

        let now = Local::now();
        let current_time_str = format!("{:02}:{:02}", now.hour(), now.minute());

        for rule in &self.rules {
            // 1. IP Check
            if let Some(ips) = &rule.ips {
                let mut match_ip = false;
                for cidr_str in ips {
                    if let Ok(cidr) = cidr_str.parse::<IpCidr>() {
                        if cidr.contains(&ip_addr) { match_ip = true; break; }
                    } else if cidr_str == "0.0.0.0/0" {
                         match_ip = true; break;
                    }
                }
                if !match_ip { continue; }
            }

            // 2. User Check
            if let Some(users) = &rule.users {
                if !users.contains(&user.to_string()) { continue; }
            }

            // 3. Database Check
            if let Some(dbs) = &rule.databases {
                 if !dbs.contains(&db.to_string()) { continue; }
            }

            // 4. Time Check
            if let Some(range) = &rule.time_range {
                 let parts: Vec<&str> = range.split('-').collect();
                 if parts.len() == 2 {
                     let start = parts[0];
                     let end = parts[1];
                     if current_time_str < start.to_string() || current_time_str > end.to_string() {
                         continue;
                     }
                 }
            }

            info!("Guardian: Connection matched rule '{}' -> {:?}", rule.name, rule.action);
            
            // Convert block lists to bytes for fast searching
            let block_queries = rule.block_queries.clone().unwrap_or_default()
                .iter().map(|s| s.to_uppercase().as_bytes().to_vec()).collect();
                
            let block_tables = rule.block_tables.clone().unwrap_or_default()
                .iter().map(|s| s.as_bytes().to_vec()).collect();

            return ConnectionContext {
                action: rule.action.clone(),
                block_queries,
                block_tables,
            };
        }

        // Default: Allow if no rule matches? Or Inspect?
        // Safe default: Inspect with no specific blocks (effectively allow but generic checks if added later)
        ConnectionContext { action: Action::INSPECT, block_queries: vec![], block_tables: vec![] }
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
                 warn!("Guardian Blocked Query: Command '{:?}' detected.", String::from_utf8_lossy(blocked_cmd));
                 return false;
             }
        }

        // 4. Block Tables
        for blocked_table in &context.block_tables {
             if contains_ascii(query, blocked_table) {
                 warn!("Guardian Blocked Query: Table '{:?}' access detected.", String::from_utf8_lossy(blocked_table));
                 return false;
             }
        }

        true 
    }
}

// Byte-level search utils (Borrowed from main.rs, could be shared in utils.rs)
fn contains_ignore_case_ascii(haystack: &[u8], needle: &[u8]) -> bool {
    if haystack.len() < needle.len() { return false; }
    haystack.windows(needle.len()).any(|window| window.eq_ignore_ascii_case(needle))
}

fn contains_ascii(haystack: &[u8], needle: &[u8]) -> bool {
    if haystack.len() < needle.len() { return false; }
    // Memchr is faster for single byte, but for substring we use memmem
    memmem::find(haystack, needle).is_some()
}

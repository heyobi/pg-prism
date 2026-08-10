//! Guardian behaviour observed through a socket, not inferred from the code.
//!
//! AUDIT.md findings #7, #15, #17, #30 and #40 were all Predicted. These make
//! them Observed, including the ones that document a limitation rather than a
//! fix.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use pg_prism_rust::guardian::{Action, Guardian, Rule};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const WAIT: Duration = Duration::from_secs(5);

fn inspecting_guardian(block_queries: Vec<&str>, block_tables: Vec<&str>) -> Arc<Guardian> {
    Arc::new(Guardian {
        rules: vec![Rule {
            name: "inspect-everything".to_string(),
            action: Action::INSPECT,
            ips: None, // omitted means any address, of either family
            users: None,
            databases: None,
            time_range: None,
            block_queries: Some(block_queries.into_iter().map(String::from).collect()),
            block_tables: Some(block_tables.into_iter().map(String::from).collect()),
        }],
    })
}

async fn open_session(backend: &mut FakeBackend, proxy_addr: std::net::SocketAddr) -> TcpStream {
    let mut wire = proxy_v1_header("203.0.113.99", 40001);
    wire.extend_from_slice(&startup_message(&[
        ("user", "app_user"),
        ("database", "shop"),
    ]));
    let sock = connect_and_send(proxy_addr, &wire).await.unwrap();

    let captured = std::mem::replace(&mut backend.captured, tokio::sync::oneshot::channel().1);
    with_timeout(WAIT, captured)
        .await
        .expect("startup never reached the backend")
        .expect("capture dropped");
    sock
}

fn query(sql: &str) -> Vec<u8> {
    let mut payload = sql.as_bytes().to_vec();
    payload.push(0);
    let mut msg = vec![b'Q'];
    msg.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
    msg.extend_from_slice(&payload);
    msg
}

enum Verdict {
    Blocked,
    ReachedBackend(String),
}

async fn send_query(guardian: Arc<Guardian>, sql: &str) -> Verdict {
    let mut backend = spawn_fake_backend().await;
    let proxy = spawn_proxy_once(backend.addr, guardian).await;
    let mut sock = open_session(&mut backend, proxy).await;

    sock.write_all(&query(sql)).await.unwrap();
    sock.flush().await.unwrap();

    // Whichever happens first: the backend sees it, or the client gets an error.
    tokio::select! {
        frame = backend.next_frame(Duration::from_secs(2)) => {
            match frame {
                Some(f) => Verdict::ReachedBackend(f.text()),
                None => Verdict::Blocked,
            }
        }
        n = async {
            let mut buf = vec![0u8; 256];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            (n, buf)
        } => {
            let (n, buf) = n;
            assert!(n > 0 && buf[0] == b'E', "expected an ErrorResponse, got {:?}", &buf[..n]);
            Verdict::Blocked
        }
    }
}

// ---------------------------------------------------------------------------
// Finding #7: the 1 KB inspection cliff
// ---------------------------------------------------------------------------

/// The baseline: a short blocked statement really is blocked.
#[tokio::test]
async fn a_short_blocked_statement_is_refused() {
    let g = inspecting_guardian(vec!["DROP"], vec![]);
    match send_query(g, "DROP TABLE secrets").await {
        Verdict::Blocked => {}
        Verdict::ReachedBackend(sql) => panic!("Guardian let it through: {:?}", sql),
    }
}

/// **Finding #7, now Observed.** Guardian inspects only Query and Parse
/// messages whose payload is under 1 KB. Padding the statement past that
/// threshold skips inspection completely, so every block rule is bypassed by
/// about a kilobyte of whitespace.
///
/// This test asserts the bypass on purpose. It is the documented limit of the
/// feature, not a defect to be fixed by tightening the threshold: raising it
/// only moves the number, and inspecting everything would mean parsing every
/// statement, which is what the proxy explicitly does not do.
///
/// If this test ever starts failing, the inspection rule changed and the README
/// and the talk both need updating.
#[tokio::test]
async fn padding_past_one_kilobyte_bypasses_every_block_rule() {
    let g = inspecting_guardian(vec!["DROP"], vec!["secrets"]);

    // Payload is the statement plus a trailing NUL, and the cliff is at 1024.
    let padding = " ".repeat(1024);
    let sql = format!("DROP TABLE secrets; --{}", padding);
    assert!(
        sql.len() + 1 >= 1024,
        "the padding must clear the threshold"
    );

    match send_query(g, &sql).await {
        Verdict::ReachedBackend(seen) => {
            assert!(seen.starts_with("DROP TABLE secrets;"));
        }
        Verdict::Blocked => {
            panic!(
                "Guardian blocked a padded statement. The 1 KB inspection cliff \
                 is documented in the README and demonstrated in the talk; if \
                 the behaviour changed, update both."
            );
        }
    }
}

/// Just under the threshold, the same statement is still caught. Pins the
/// boundary so the documented number stays true.
#[tokio::test]
async fn just_under_the_threshold_is_still_inspected() {
    let g = inspecting_guardian(vec!["DROP"], vec![]);
    let sql = format!("DROP TABLE secrets; --{}", " ".repeat(900));
    assert!(sql.len() + 1 < 1024);

    match send_query(g, &sql).await {
        Verdict::Blocked => {}
        Verdict::ReachedBackend(_) => panic!("a sub-1 KB statement escaped inspection"),
    }
}

// ---------------------------------------------------------------------------
// Findings #17 and #40: what substring matching actually does
// ---------------------------------------------------------------------------

/// **Finding #17, fixed.** PostgreSQL folds unquoted identifiers, so `SECRETS`
/// and `secrets` are the same table. Matching is now ASCII case-insensitive.
#[tokio::test]
async fn table_matching_catches_a_different_case_spelling() {
    let g = inspecting_guardian(vec![], vec!["secrets"]);
    match send_query(g, "SELECT * FROM SECRETS").await {
        Verdict::Blocked => {}
        Verdict::ReachedBackend(sql) => panic!("case bypass still works: {:?}", sql),
    }
}

/// A table whose name merely starts with the blocked one is a different table
/// and must get through.
#[tokio::test]
async fn a_table_with_a_shared_prefix_is_not_blocked() {
    let g = inspecting_guardian(vec![], vec!["secrets"]);
    match send_query(g, "SELECT * FROM secrets_backup").await {
        Verdict::ReachedBackend(_) => {}
        Verdict::Blocked => panic!("secrets_backup is a different table"),
    }
}

/// **Finding #40, fixed.** A blocked keyword inside an unrelated identifier is
/// no longer a match.
#[tokio::test]
async fn a_keyword_inside_an_identifier_is_not_blocked() {
    let g = inspecting_guardian(vec!["DROP"], vec![]);
    match send_query(g, "SELECT * FROM eavesdropping").await {
        Verdict::ReachedBackend(_) => {}
        Verdict::Blocked => panic!("eavesdropping is not a DROP"),
    }
}

/// **Documented limitation.** Guardian searches the raw statement, so a keyword
/// in a comment still matches. Skipping comments would require recognising
/// string literals, dollar quoting and escapes, which is a lexer, and writing
/// one badly would produce false *negatives* instead. It errs towards blocking.
#[tokio::test]
async fn a_keyword_in_a_comment_is_still_blocked() {
    let g = inspecting_guardian(vec!["DROP"], vec![]);
    match send_query(g, "SELECT 1 -- do not DROP this").await {
        Verdict::Blocked => {}
        Verdict::ReachedBackend(_) => panic!("Guardian now parses SQL; update the docs"),
    }
}

// ---------------------------------------------------------------------------
// Finding #15: address families
// ---------------------------------------------------------------------------

/// A rule with no `ips` matches any client, of either family.
#[test]
fn a_rule_without_addresses_matches_both_families() {
    let g = inspecting_guardian(vec!["DROP"], vec![]);
    for ip in ["10.0.0.5", "2001:db8::1"] {
        let ctx = g.check_connection(ip, "app_user", "shop");
        assert_eq!(ctx.action, Action::INSPECT);
        assert!(
            !ctx.block_queries.is_empty(),
            "{} did not pick up the rule's block list",
            ip
        );
    }
}

/// **Finding #15, now Observed.** `0.0.0.0/0` is the IPv4 default route, not a
/// catch-all. An IPv6 client does not match it, falls through to the permissive
/// default, and is filtered by nothing.
///
/// The semantics are deliberately left exact rather than redefined; the loader
/// warns about rules written this way instead.
#[test]
fn the_ipv4_default_route_does_not_cover_ipv6_clients() {
    let g = Arc::new(Guardian {
        rules: vec![Rule {
            name: "catch-all-that-is-not".to_string(),
            action: Action::INSPECT,
            ips: Some(vec!["0.0.0.0/0".to_string()]),
            users: None,
            databases: None,
            time_range: None,
            block_queries: Some(vec!["DROP".to_string()]),
            block_tables: None,
        }],
    });

    let v4 = g.check_connection("10.0.0.5", "app_user", "shop");
    assert!(!v4.block_queries.is_empty(), "IPv4 client should match");

    let v6 = g.check_connection("2001:db8::1", "app_user", "shop");
    assert!(
        v6.block_queries.is_empty(),
        "if this rule now matches IPv6, finding #15 changed and the loader \
         warning is wrong"
    );
}

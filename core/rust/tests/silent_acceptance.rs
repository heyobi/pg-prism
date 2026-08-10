//! The "unrecognised input, carry on" audit pass (AUDIT.md §14).
//!
//! Three bugs found separately — CancelRequest corrupted, a non-ASCII
//! `application_name` truncated away, protocol 3.2 skipping Guardian — turned out
//! to be the same shape: the code did not recognise something, did nothing about
//! it, and produced a result that still looked plausible.
//!
//! Every test here **asserts the current, wrong behaviour on purpose**, in the
//! same style as the documented-limitation tests in `guardian.rs`. Nothing is
//! fixed in this pass. When a finding is fixed, its test flips and says so,
//! which is the point: none of these can regress into silence again.

use pg_prism_rust::guardian::Guardian;

fn temp_config(tag: &str, contents: &str) -> String {
    use std::io::Write;
    let mut path = std::env::temp_dir();
    path.push(format!(
        "pg-prism-silent-{}-{}-{:?}.yaml",
        tag,
        std::process::id(),
        std::thread::current().id()
    ));
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(contents.as_bytes()).unwrap();
    path.to_string_lossy().to_string()
}

/// **Finding #53.** `Rule` does not carry `#[serde(deny_unknown_fields)]`, so a
/// misspelled field is dropped in silence. The rule still loads, still matches,
/// and blocks nothing — and `Guardian loaded with 1 rules` appears in the log.
///
/// This is the worst instance of the shape found in this pass, because the
/// operator gets positive confirmation that a rule they wrote is active.
#[test]
fn a_misspelled_rule_field_is_silently_ignored() {
    let path = temp_config(
        "unknown-field",
        "rules:\n  - name: block-drops\n    action: INSPECT\n    block_querys: [\"DROP\"]\n",
    );
    let g = Guardian::load(&path).expect("current behaviour: the typo is accepted");
    assert_eq!(g.rules.len(), 1, "the rule loads and is counted");

    let ctx = g.check_connection("10.0.0.1", "alice", "shop");
    assert!(
        ctx.block_queries.is_empty(),
        "the misspelled list did not survive parsing"
    );
    assert!(
        Guardian::check_query(b"DROP TABLE secrets", &ctx),
        "documented defect #53: a rule written to block DROP blocks nothing, and \
         nothing anywhere says so. When #53 is fixed, loading must fail instead."
    );
    let _ = std::fs::remove_file(&path);
}

/// A malformed *top-level* shape is caught, which is the contrast that makes #53
/// worth fixing: the failure is not that serde is lenient everywhere, it is that
/// it is strict about the container and lenient about the contents.
#[test]
fn a_malformed_toplevel_shape_is_correctly_fatal() {
    let path = temp_config(
        "toplevel",
        "rule:\n  - name: block-drops\n    action: INSPECT\n    block_queries: [\"DROP\"]\n",
    );
    let err = Guardian::load(&path).expect_err("a missing `rules` key must be fatal");
    assert!(err.to_string().contains("Refusing to start"));
    let _ = std::fs::remove_file(&path);
}

/// **Finding #54.** `check_connection` matches CIDRs with `.unwrap_or(false)`, so
/// an entry that does not parse silently matches nothing. On a DENY rule the
/// addresses behind that entry are no longer denied.
///
/// `warn_about_unreachable_rules` does not catch it: it warns only when *every*
/// entry fails to parse, so one bad entry among several is completely silent.
///
/// Note the inconsistency this documents. `TrustedProxies::parse` refuses to
/// start on exactly the same malformed input (`trust.rs`,
/// `parse_rejects_malformed_entries`). Two allowlists in one binary, opposite
/// failure directions.
#[test]
fn one_unparseable_cidr_silently_removes_addresses_from_a_deny_rule() {
    let path = temp_config(
        "bad-cidr",
        "rules:\n  - name: deny-office\n    action: DENY\n    \
         ips: [\"10.0.0.0/8\", \"192.168.1.0/244\"]\n",
    );
    let g = Guardian::load(&path).expect("current behaviour: the bad entry is accepted");

    assert_eq!(
        g.check_connection("10.1.2.3", "alice", "shop").action,
        pg_prism_rust::guardian::Action::DENY,
        "the entry that parses still works"
    );
    assert_ne!(
        g.check_connection("192.168.1.50", "alice", "shop").action,
        pg_prism_rust::guardian::Action::DENY,
        "documented defect #54: /244 is not a prefix length, the entry is dropped, \
         and every address behind it escapes the DENY without a word in the log"
    );
    let _ = std::fs::remove_file(&path);
}

/// **Finding #55.** `time_in_range` returns false for a malformed range, and the
/// comment above it calls that "the safer direction to fail". That is true for an
/// ALLOW rule and false for a DENY rule: a non-matching DENY is a DENY that does
/// not happen.
#[test]
fn a_malformed_time_range_silently_disables_a_deny_rule() {
    let path = temp_config(
        "bad-time",
        "rules:\n  - name: deny-nights\n    action: DENY\n    time_range: \"10pm-6am\"\n",
    );
    let g = Guardian::load(&path).expect("load failed");
    assert_ne!(
        g.check_connection("10.0.0.1", "alice", "shop").action,
        pg_prism_rust::guardian::Action::DENY,
        "documented defect #55: the window never matches, so the rule never denies, \
         at any hour of the day"
    );
    let _ = std::fs::remove_file(&path);
}

/// **Finding #56.** `main.rs` computes TLS as `value.to_lowercase() == \"true\"`.
/// Every other spelling of yes — including a stray trailing space — silently
/// means plaintext, and the only log line is the cheerful "SSL termination is
/// disabled."
///
/// This mirrors the exact expression in `main.rs` rather than calling it, because
/// the expression is inline there. If `main.rs` changes, this test must be
/// updated with it; that coupling is noted in AUDIT.md §14.
#[test]
fn ssl_enabled_accepts_only_one_spelling_of_yes() {
    let tls_on = |raw: &str| raw.to_lowercase() == "true";

    assert!(tls_on("true"));
    assert!(tls_on("TRUE"), "case is folded");

    for raw in ["1", "yes", "on", "y", " true", "true ", "flase"] {
        assert!(
            !tls_on(raw),
            "documented defect #56: SSL_ENABLED={:?} silently disables TLS",
            raw
        );
    }
}

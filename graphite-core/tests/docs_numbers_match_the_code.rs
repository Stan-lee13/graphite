//! The numbers the live documentation states must be the numbers the code
//! has.
//!
//! The 2026-09-29 audit (A6-20..A6-28) found the same facts stated four
//! different ways across the README, ARCHITECTURE, CURRENT and the SAK
//! README: 1,647 mutations where the corpus holds 1,659, "11 patterns / 13
//! checks" and "11 / 14" where the Risk Engine runs 16, 12 non-inherent
//! residual codes where there are 13, and "5 views" where the dashboard has 8.
//! Nothing was wrong on purpose: each was true once, and nothing compared
//! them afterwards. `tests/docs_match_the_registry.rs` already pins the
//! manifest counts; this does the same for every other count a reader would
//! use to judge coverage (roadmap gap R-P13, Constitution P16).
//!
//! Each count is DERIVED here from the source of truth, never written as a
//! literal, and every place a live document states that kind of number is
//! found by scanning, so a new stale copy fails too. Dated reports and the
//! dated sections of SECURITY.md and the CHANGELOG are history by the
//! repository's own rule and are not scanned.

use graphite_core::verification::UnobservedCode;

const README: &str = include_str!("../../README.md");
const ARCHITECTURE: &str = include_str!("../../ARCHITECTURE.md");
const CURRENT: &str = include_str!("../../docs/CURRENT.md");
const CORE_README: &str = include_str!("../README.md");
const SAK_README: &str = include_str!("../../integrations/solana-agent-kit/README.md");
const GUARD_README: &str = include_str!("../../integrations/agent-guard/README.md");

const LIVE_DOCS: &[(&str, &str)] = &[
    ("README.md", README),
    ("ARCHITECTURE.md", ARCHITECTURE),
    ("docs/CURRENT.md", CURRENT),
    ("graphite-core/README.md", CORE_README),
    ("integrations/solana-agent-kit/README.md", SAK_README),
    ("integrations/agent-guard/README.md", GUARD_README),
];

/// Every number written immediately before one of `words` (optionally joined
/// by a space or hyphen, optionally with `between` in the gap), as
/// `(line number, number)`. Thousands separators are allowed.
fn numbers_before(doc: &str, words: &[&str], between: &[&str]) -> Vec<(usize, u64)> {
    let mut out = Vec::new();
    for (n, line) in doc.lines().enumerate() {
        for word in words {
            let mut from = 0;
            while let Some(at) = line[from..].find(word) {
                let at = from + at;
                from = at + word.len();
                let mut head = line[..at].trim_end_matches([' ', '-']);
                for b in between {
                    if let Some(h) = head.strip_suffix(b) {
                        head = h.trim_end_matches([' ', '-']);
                    }
                }
                let digits: String = head
                    .chars()
                    .rev()
                    .take_while(|c| c.is_ascii_digit() || *c == ',')
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                let digits = digits.trim_start_matches(',').replace(',', "");
                if let Ok(v) = digits.parse::<u64>() {
                    out.push((n + 1, v));
                }
            }
        }
    }
    out
}

/// Every live statement of a count must equal `truth`. With `context`, only
/// lines that also mention one of those words (case-insensitive) are
/// statements of this count, so "3 checks run first" in unrelated prose is not
/// read as the Risk Engine's.
fn assert_every_statement(
    what: &str,
    truth: u64,
    words: &[&str],
    between: &[&str],
    context: &[&str],
) {
    let mut found = 0;
    let mut wrong = Vec::new();
    for (name, doc) in LIVE_DOCS {
        let lines: Vec<String> = doc.lines().map(str::to_lowercase).collect();
        for (line, v) in numbers_before(doc, words, between) {
            if !context.is_empty() && !context.iter().any(|c| lines[line - 1].contains(c)) {
                continue;
            }
            found += 1;
            if v != truth {
                wrong.push(format!("{name}:{line}: says {v}"));
            }
        }
    }
    assert!(
        found > 0,
        "no live document states the {what}; the scan is broken"
    );
    assert!(
        wrong.is_empty(),
        "the {what} is {truth}, but:\n{}",
        wrong.join("\n")
    );
}

/// The cross-language corpus's byte-level mutations.
#[test]
fn the_mutation_count_is_the_corpus() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/artifacts/sak_bridge_corpus.json"))
            .expect("corpus");
    let truth = corpus["mutations"].as_array().expect("mutations").len() as u64;
    assert_every_statement(
        "number of byte-level mutations",
        truth,
        &["mutation"],
        &["byte-level"],
        &[],
    );
}

/// The Risk Engine's checks (`CHECKED_PATTERNS`, itself pinned to the
/// labelled checks in `assess` by a unit test).
#[test]
fn the_risk_check_count_is_the_engine() {
    let truth = graphite_core::risk_engine::CHECKED_PATTERNS as u64;
    assert_every_statement(
        "number of risk checks",
        truth,
        &["checks"],
        &["risk"],
        &["risk", "pattern"],
    );
}

/// The residual codes a policy must accept by name: every code that is not
/// inherent to a single-transaction verifier.
#[test]
fn the_non_inherent_residual_count_is_the_enum() {
    let truth = UnobservedCode::ALL.iter().filter(|c| !c.inherent()).count() as u64;
    assert_every_statement(
        "number of non-inherent residual codes",
        truth,
        &["non-inherent code"],
        &[],
        &[],
    );
}

/// The dashboard's views: one `*View.tsx` per view.
#[test]
fn the_dashboard_view_count_is_the_source() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../dashboard/src/views");
    let truth = std::fs::read_dir(&dir)
        .expect("dashboard/src/views")
        .flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            n.ends_with("View.tsx")
        })
        .count() as u64;
    assert_every_statement(
        "number of dashboard views",
        truth,
        &[" views"],
        &[],
        &["dashboard"],
    );
}

/// The scan finds numbers the way a reader would, and not elsewhere.
#[test]
fn the_scan_reads_numbers_as_written() {
    let doc =
        "a 1,659 byte-level mutations b\nthe 1,659-mutation corpus\n16 risk checks, 3 things\n";
    assert_eq!(
        numbers_before(doc, &["mutation"], &["byte-level"]),
        vec![(1, 1659), (2, 1659)]
    );
    assert_eq!(numbers_before(doc, &["checks"], &["risk"]), vec![(3, 16)]);
    assert!(numbers_before("no number here: mutations", &["mutation"], &[]).is_empty());
}

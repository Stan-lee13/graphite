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
//!
//! The audit of 2026-10-20 found the drift again, in places this did not yet
//! read: "23 structural risk checks" in ARCHITECTURE where the engine runs 16,
//! an 11,450-fixture corpus where 12,687 were committed, and the Rust test
//! count stated four different ways (a badge, the README, ARCHITECTURE,
//! CONTRIBUTING). So CONTRIBUTING.md and ROADMAP.md are scanned too, the
//! instruction count and the corpus size are pinned here, and test counts —
//! which change with every commit and so cannot be pinned — are allowed in
//! exactly one live document, `docs/CURRENT.md`, which every other one links.

use graphite_core::verification::UnobservedCode;

const README: &str = include_str!("../../README.md");
const ARCHITECTURE: &str = include_str!("../../ARCHITECTURE.md");
const CURRENT: &str = include_str!("../../docs/CURRENT.md");
const CORE_README: &str = include_str!("../README.md");
const SAK_README: &str = include_str!("../../integrations/solana-agent-kit/README.md");
const GUARD_README: &str = include_str!("../../integrations/agent-guard/README.md");
const CONTRIBUTING: &str = include_str!("../../CONTRIBUTING.md");
const ROADMAP: &str = include_str!("../../ROADMAP.md");
// Round 34 (R33 DOC-19): the operator runbooks, the auditors' hand-off pack
// and the grant proposal state counts a reader relies on, and drifted.
const OPS_CHECKLIST: &str = include_str!("../../docs/ops/production-checklist.md");
const OPS_README: &str = include_str!("../../docs/ops/README.md");
const OPS_KEYS: &str = include_str!("../../docs/ops/keys.md");
const OPS_INSTALL: &str = include_str!("../../docs/ops/install.md");
const HANDOFF: &str = include_str!("../../docs/audit-handoff/README.md");
const GRANT: &str = include_str!("../../docs/solana-foundation-grant-proposal.md");

const LIVE_DOCS: &[(&str, &str)] = &[
    ("README.md", README),
    ("ARCHITECTURE.md", ARCHITECTURE),
    ("docs/CURRENT.md", CURRENT),
    ("graphite-core/README.md", CORE_README),
    ("integrations/solana-agent-kit/README.md", SAK_README),
    ("integrations/agent-guard/README.md", GUARD_README),
    ("CONTRIBUTING.md", CONTRIBUTING),
    ("ROADMAP.md", ROADMAP),
    ("docs/ops/production-checklist.md", OPS_CHECKLIST),
    ("docs/ops/README.md", OPS_README),
    ("docs/ops/keys.md", OPS_KEYS),
    ("docs/ops/install.md", OPS_INSTALL),
    ("docs/audit-handoff/README.md", HANDOFF),
    ("docs/solana-foundation-grant-proposal.md", GRANT),
];

/// The number written at the end of `head` (after trailing spaces and
/// hyphens, and after any one of `between`), thousands separators allowed.
fn trailing_number(head: &str, between: &[&str]) -> Option<u64> {
    let mut head = head.trim_end_matches([' ', '-']);
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
    digits.trim_start_matches(',').replace(',', "").parse().ok()
}

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
                if let Some(v) = trailing_number(&line[..at], between) {
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

/// The intent grants (`intent_grants::GRANTS`). Round 41 (external review
/// D-11): CURRENT and the handoff said 27 after D-2 had removed `update_offer`
/// and left 26; nothing held the number.
#[test]
fn the_intent_grant_count_is_the_table() {
    assert_every_statement(
        "number of intent grants",
        graphite_core::intent_grants::GRANTS.len() as u64,
        &["grants"],
        &["intent"],
        &["intent_grants", "intent grant"],
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

/// Every "N manifests / M instructions" (also "N manifests, M instructions",
/// "N JSON protocol manifests (M instructions)", any case) in `doc`, as
/// `(line number, N, M)`.
fn manifest_instruction_pairs(doc: &str) -> Vec<(usize, u64, u64)> {
    let mut out = Vec::new();
    for (n, line) in doc.lines().enumerate() {
        let lower = line.to_lowercase();
        let mut from = 0;
        while let Some(at) = lower[from..].find("manifests") {
            let at = from + at;
            from = at + "manifests".len();
            let Some(manifests) =
                trailing_number(&lower[..at], &["json protocol", "protocol", "seed"])
            else {
                continue;
            };
            let rest = lower[from..].trim_start_matches([' ', '/', ',', '(']);
            let digits: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == ',')
                .collect();
            if !rest[digits.len()..]
                .trim_start()
                .starts_with("instructions")
            {
                continue;
            }
            if let Ok(instructions) = digits.replace(',', "").parse::<u64>() {
                out.push((n + 1, manifests, instructions));
            }
        }
    }
    out
}

/// The registry's size wherever a live document states it as a pair: the
/// manifests the loader loads and the instructions they declare
/// (`docs_match_the_registry.rs` pins the README's headline and badge; this
/// reads every other statement, including CONTRIBUTING and ROADMAP).
#[test]
fn the_manifest_and_instruction_counts_are_the_registry() {
    let registry = graphite_core::manifest::load_seed_manifests();
    let manifests = registry.list().len() as u64;
    let instructions: u64 = registry
        .list()
        .iter()
        .map(|m| m.instructions.len() as u64)
        .sum();
    let mut found = 0;
    let mut wrong = Vec::new();
    for (name, doc) in LIVE_DOCS {
        for (line, m, i) in manifest_instruction_pairs(doc) {
            found += 1;
            if (m, i) != (manifests, instructions) {
                wrong.push(format!(
                    "{name}:{line}: says {m} manifests / {i} instructions"
                ));
            }
        }
    }
    assert!(
        found > 0,
        "no live document states the registry's size; the scan is broken"
    );
    assert!(
        wrong.is_empty(),
        "the registry is {manifests} manifests / {instructions} instructions, but:\n{}",
        wrong.join("\n")
    );
}

/// The committed regression corpus: one entry per fixture in
/// `fixtures/corpus/meta/corpus_manifest.json`.
#[test]
fn the_corpus_size_is_the_committed_corpus() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/corpus/meta/corpus_manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("corpus manifest"))
            .expect("corpus manifest is JSON");
    let truth = manifest.as_array().expect("one entry per fixture").len() as u64;
    assert_every_statement(
        "number of fixtures in the committed regression corpus",
        truth,
        &["fixture committed regression corpus"],
        &[],
        &[],
    );
}

/// A test count changes with every commit, so no test pins one; instead
/// exactly one live document states them (`docs/CURRENT.md`, "Numbers") and
/// every other one links there. The audit of 2026-10-20 found 1923 on the
/// badge, 1,934 in the README, 1,849 in three other places and 341 / 1,594 in
/// CONTRIBUTING, all at once.
#[test]
fn test_counts_are_stated_only_in_current() {
    const WORDS: &[&str] = &["Rust tests", "Rust_Tests", "tests passing", "tests pass"];
    let mut elsewhere = Vec::new();
    for (name, doc) in LIVE_DOCS {
        let stated = numbers_before(doc, WORDS, &[]);
        if *name == "docs/CURRENT.md" {
            assert!(
                !stated.is_empty(),
                "docs/CURRENT.md no longer states the Rust test count; the other documents link there"
            );
            continue;
        }
        for (line, v) in stated {
            elsewhere.push(format!("{name}:{line}: states {v}"));
        }
    }
    assert!(
        elsewhere.is_empty(),
        "test counts belong in docs/CURRENT.md only (link there instead):\n{}",
        elsewhere.join("\n")
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
    assert_eq!(
        manifest_instruction_pairs(
            "## Supported Protocols (137 Manifests / 3,541 Instructions)\n\
             137 JSON protocol manifests (3,541 instructions)\n\
             137 manifests, 3,541 instructions, 113 battle-tested\n\
             eight more manifests (3,504 instructions at the time)\n"
        ),
        vec![(1, 137, 3541), (2, 137, 3541), (3, 137, 3541)]
    );
    assert_eq!(
        numbers_before(
            "a 13,013-fixture committed regression corpus",
            &["fixture committed regression corpus"],
            &[]
        ),
        vec![(1, 13013)]
    );
}

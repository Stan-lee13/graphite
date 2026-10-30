//! Round 40 (R39-CB-15): `graphite explain` and `graphite verify` never put a
//! caller's control characters on the operator's terminal.
//!
//! `explain` printed the request's text as given wherever a reason quoted it:
//! an input file's ESC sequences (clear the screen, recolour, retitle the
//! window) ran in the operator's terminal, and a U+202E RIGHT-TO-LEFT
//! OVERRIDE reversed the rest of the line it sat in — a line the operator
//! reads to decide whether to sign. Both now arrive escaped (`\u{1b}`,
//! `\u{202e}`). `verify`'s JSON escapes them as JSON does, so it parses to the
//! same value.
#![cfg(feature = "cli")]

use std::path::{Path, PathBuf};
use std::process::Command;

/// The one free-text field of a request: the Core refuses anything but
/// printable ASCII in the intent type, the addresses and the discriminator.
/// The drainer plugin's finding quotes it (a reward-shaped request on a
/// transaction that debits), and `explain` printed that finding raw.
const HOSTILE_TEXT: &str = "claim my airdrop \u{1b}[2J\u{1b}[32mAPPROVED\u{1b}[0m \u{202e}dneirf ot\u{1b}]0;pwned\u{7} \u{85}\u{2066}x";

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "graphite-r40-escapes-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn example() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/verify-input.json")
}

fn hostile_input(dir: &Path) -> PathBuf {
    let mut input: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(example()).unwrap()).unwrap();
    input["proposed_intent"]["raw_natural_language"] = HOSTILE_TEXT.into();
    let path = dir.join("hostile.json");
    std::fs::write(&path, serde_json::to_vec(&input).unwrap()).unwrap();
    path
}

fn graphite(dir: &Path, args: &[&str]) -> (String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_graphite"));
    for (k, _) in std::env::vars() {
        if k.starts_with("GRAPHITE_") {
            c.env_remove(k);
        }
    }
    let out = c
        .env("GRAPHITE_DATA_DIR", dir.join("data"))
        .env("GRAPHITE_REGISTRY_STATE", dir.join("no-registry.json"))
        .args(args)
        .output()
        .unwrap();
    (
        String::from_utf8(out.stdout).expect("stdout is UTF-8"),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// What a terminal would act on rather than show.
fn raw_controls(s: &str) -> Vec<char> {
    s.chars()
        .filter(|c| {
            (c.is_control() && *c != '\n')
                || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .collect()
}

#[test]
fn explain_prints_a_requests_escape_sequences_escaped() {
    let dir = temp_dir("explain");
    let file = hostile_input(&dir);
    let (out, err) = graphite(&dir, &["explain", "--file", file.to_str().unwrap()]);
    assert!(out.contains("VERDICT"), "explain ran: {out}\n{err}");
    assert_eq!(raw_controls(&out), Vec::<char>::new(), "{out:?}");
    // The attack's text is still there, legible, each escape spelled out —
    // in the drainer finding that quotes it.
    let finding = out
        .lines()
        .find(|l| l.contains("reward-shaped request"))
        .unwrap_or_else(|| panic!("the drainer finding is printed: {out}"));
    assert!(
        finding.contains("\\u{1b}[2J\\u{1b}[32mAPPROVED\\u{1b}[0m")
            && finding.contains("\\u{202e}dneirf ot\\u{1b}]0;pwned\\u{7}"),
        "{finding}"
    );
    // Benign control: an ordinary request prints as it did.
    let (plain, _) = graphite(&dir, &["explain", "--file", example().to_str().unwrap()]);
    assert!(
        plain.contains("  intent       transfer — \"Transfer 1 SOL to friend\""),
        "{plain}"
    );
    assert!(!plain.contains("\\u{"), "{plain}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn verify_json_escapes_them_and_parses_to_the_same_value() {
    let dir = temp_dir("verify");
    let file = hostile_input(&dir);
    let (out, err) = graphite(&dir, &["verify", "--file", file.to_str().unwrap()]);
    assert_eq!(raw_controls(&out), Vec::<char>::new(), "{out:?}");
    let parsed: serde_json::Value =
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}\n{err}"));
    // The verdict quotes the request (the drainer finding), escaped as JSON
    // escapes, and the value it parses to is the text itself.
    assert!(out.contains("\\u202e") && out.contains("\\u001b"), "{out}");
    let findings = parsed["risk_verdict"]["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f["reason"].as_str().unwrap().contains(HOSTILE_TEXT)),
        "the parsed value is unchanged: {findings:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

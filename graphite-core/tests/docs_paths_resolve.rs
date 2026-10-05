//! A live document does not point at a file that is not there.
//!
//! R4 (review of the 2026-09-29 audit): the CHANGELOG and two AUDIT documents
//! cited `AUDIT/FINAL.md` and the round report before either existed, and
//! nothing failed. This test reads every live document — the ones that say what
//! is true now, not the dated round reports, which are history — and requires
//! every relative Markdown link, and every backticked file path, to name a file
//! in the repository. A path that names something outside the repository on
//! purpose (the sibling engineering-skill repo, the maintainer's work directory,
//! an upstream project's file) is listed in `EXTERNAL`, with why.

use std::path::{Path, PathBuf};

/// Documents that describe the repository as it is.
const LIVE: &[&str] = &[
    "README.md",
    "SECURITY.md",
    "ARCHITECTURE.md",
    "ROADMAP.md",
    "CONTRIBUTING.md",
    "docs/CURRENT.md",
    "graphite-core/README.md",
    "graphite-core/CHANGELOG.md",
    "graphite-core/scripts/README.md",
    "sdk/typescript/README.md",
    "integrations/solana-agent-kit/README.md",
    "integrations/agent-guard/README.md",
    "integrations/vercel-ai/README.md",
    "integrations/mcp-server/README.md",
    "python-ai-layer/README.md",
    "dashboard/README.md",
    "AUDIT/00-map.md",
    "AUDIT/01-findings.md",
    "AUDIT/02-roadmap-gap.md",
    "AUDIT/FINAL.md",
];

/// Paths that are outside this repository by design.
const EXTERNAL: &[&str] = &[
    // The sibling repository holding the Constitution and the roadmap.
    "graphite-engineering-skill/",
    // The maintainer's work directory, cited as outside the repository.
    "graphite-audit-work/",
    // Upstream projects' IDL files, named in historical CHANGELOG entries.
    "sdk/src/idl/drift.json",
    "src/idl/klend.json",
];

/// Where a backticked path is looked up: beside the document, at the root, and
/// in the directories documents abbreviate paths from.
const BASES: &[&str] = &[
    "",
    "graphite-core",
    "integrations/solana-agent-kit",
    "integrations/agent-guard",
    "integrations/vercel-ai",
    "integrations/mcp-server",
    ".github",
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("graphite-core sits in the repository root")
        .to_path_buf()
}

fn is_external(target: &str) -> bool {
    EXTERNAL.iter().any(|e| target.starts_with(e))
}

fn markdown_links(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(i) = rest.find("](") {
        let after = &rest[i + 2..];
        match after.find(')') {
            Some(j) => {
                out.push(after[..j].to_string());
                rest = &after[j + 1..];
            }
            None => break,
        }
    }
    out
}

fn backticked_paths(line: &str) -> Vec<String> {
    const EXT: &[&str] = &[
        ".md", ".rs", ".ts", ".mts", ".json", ".py", ".go", ".yml", ".toml", ".sh", ".mjs",
        ".allow",
    ];
    line.split('`')
        .skip(1)
        .step_by(2)
        .filter(|s| {
            s.contains('/')
                && !s.contains('*')
                && !s.contains(' ')
                && EXT.iter().any(|e| s.ends_with(e))
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_./-".contains(c))
        })
        .map(str::to_string)
        .collect()
}

#[test]
fn every_path_a_live_document_names_exists() {
    let root = root();
    let mut missing = Vec::new();
    for doc in LIVE {
        let path = root.join(doc);
        let Ok(text) = std::fs::read_to_string(&path) else {
            missing.push(format!("{doc}: the document itself is missing"));
            continue;
        };
        let dir = path
            .parent()
            .expect("a document has a directory")
            .to_path_buf();
        for (n, line) in text.lines().enumerate() {
            for target in markdown_links(line) {
                let target = target.split('#').next().unwrap_or_default();
                if target.is_empty() || target.contains(':') || is_external(target) {
                    continue;
                }
                if !dir.join(target).exists() {
                    missing.push(format!("{doc}:{}: link to {target}", n + 1));
                }
            }
            for target in backticked_paths(line) {
                if is_external(&target) {
                    continue;
                }
                let found = dir.join(&target).exists()
                    || BASES.iter().any(|b| root.join(b).join(&target).exists());
                if !found {
                    missing.push(format!("{doc}:{}: path {target}", n + 1));
                }
            }
        }
    }
    assert!(
        missing.is_empty(),
        "live documents name files that are not in the repository:\n{}",
        missing.join("\n")
    );
}

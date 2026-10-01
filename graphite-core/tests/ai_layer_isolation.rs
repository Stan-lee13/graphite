//! P1 ("AI assists, AI never decides"), checked mechanically.
//!
//! The Python AI layer is a separate process whose output is advisory text.
//! Until now that separation was established by reading the code
//! (`tests/ai_cannot_approve.rs` covers the plugin surface only), which is
//! the "asserted, not verified" the engineering skill's Phase 1.5 exit
//! criterion rules out (2026-09-29 audit, roadmap gap R-P5).
//!
//! This test reads every source file of the Core and its manifest, and fails
//! on anything that would let the verifier reach the AI layer: its package or
//! module names, its URL variable, its default port, an embedded Python
//! runtime, or a spawned process. A verdict can then only come from the Rust
//! in `src/`, whatever the AI layer answers or however it is compromised.

use std::path::{Path, PathBuf};

/// What would connect the verifier to the AI layer, and why each is refused.
const FORBIDDEN: &[(&str, &str)] = &[
    ("python-ai-layer", "the AI layer's package directory"),
    ("python_ai_layer", "the AI layer's package name"),
    ("intent_parser", "the AI layer's parser module"),
    (
        "GRAPHITE_AI_LAYER_URL",
        "the variable naming the AI layer's endpoint",
    ),
    ("8081", "the AI layer's default port"),
    ("pyo3", "an embedded Python runtime"),
    ("cpython", "an embedded Python runtime"),
    (
        "process::Command",
        "a spawned process (the AI layer is a process)",
    ),
    (
        "Command::new",
        "a spawned process (the AI layer is a process)",
    ),
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("src/ must be readable") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every forbidden reference in `text`, as `line: needle (why)`.
fn hits_in(text: &str) -> Vec<String> {
    let mut hits = Vec::new();
    for (n, line) in text.lines().enumerate() {
        for (needle, why) in FORBIDDEN {
            if line.contains(needle) {
                hits.push(format!("{}: `{needle}` ({why})", n + 1));
            }
        }
    }
    hits
}

#[test]
fn the_core_never_references_the_ai_layer() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    files.push(root.join("Cargo.toml"));
    // A scan that read nothing would pass vacuously.
    assert!(
        files.len() > 20,
        "expected the Core's sources, found {} files",
        files.len()
    );

    let mut hits = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("source must be UTF-8");
        let name = file
            .strip_prefix(root)
            .unwrap_or(file)
            .display()
            .to_string();
        hits.extend(hits_in(&text).into_iter().map(|h| format!("{name}:{h}")));
    }
    assert!(
        hits.is_empty(),
        "the verifier must not be able to reach the AI layer (P1):\n{}",
        hits.join("\n")
    );
}

/// The scan can fire: a source line using any one reference is caught, and
/// a clean line is not.
#[test]
fn the_scan_fires_on_each_forbidden_reference() {
    for (needle, _) in FORBIDDEN {
        let source = format!("fn f() {{}}\nlet x = {needle};\n");
        let hits = hits_in(&source);
        assert!(
            hits.iter()
                .any(|h| h.starts_with("2: ") && h.contains(needle)),
            "{needle} was not caught: {hits:?}"
        );
    }
    assert!(hits_in("fn verify() -> bool { false }").is_empty());
}

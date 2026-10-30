//! Round 36 (F-020): a `GRAPHITE_*` variable the Core does not read is a
//! decision it never sees.
//!
//! On the Round 35 code `GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWAL=1` (one letter
//! short) started the server as if nothing were set. The operator believed a
//! decision was configured; nothing read it. The server now refuses a
//! near-miss of a variable it reads, and logs any other unknown name. The
//! lists it judges by are pinned to the repository here, so a component that
//! starts reading a new name cannot be refused by a Core that does not know
//! it.

use graphite_core::operator_boundary::{
    check_env_names, unknown_env_names, AI_LAYER_ENV_PREFIX, COMPONENT_ENV_NAMES, CORE_ENV_NAMES,
};
use std::collections::BTreeSet;
use std::path::Path;

fn names_in(dir: &Path, out: &mut BTreeSet<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if p.is_dir() {
            if matches!(
                name.as_str(),
                "node_modules" | "target" | "dist" | ".git" | "out" | "__pycache__"
            ) {
                continue;
            }
            names_in(&p, out);
        } else if let Ok(text) = std::fs::read_to_string(&p) {
            let b = text.as_bytes();
            let mut i = 0;
            while let Some(at) = text[i..].find("GRAPHITE_") {
                let start = i + at;
                let boundary =
                    start == 0 || !(b[start - 1].is_ascii_alphanumeric() || b[start - 1] == b'_');
                let mut end = start + "GRAPHITE_".len();
                while end < b.len()
                    && (b[end].is_ascii_uppercase() || b[end].is_ascii_digit() || b[end] == b'_')
                {
                    end += 1;
                }
                let word = &text[start..end];
                // A prefix in prose ("GRAPHITE_SWAP_*") is not a name.
                if boundary && !word.ends_with('_') {
                    out.insert(word.to_string());
                }
                i = end;
            }
        }
    }
}

fn repo() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Every name the Core's source mentions is one it reads, or one another
/// component reads (its comments refer to the guard's), or this file's
/// deliberately unknown one.
#[test]
fn every_name_the_core_mentions_is_listed() {
    let mut found = BTreeSet::new();
    names_in(&repo().join("graphite-core/src"), &mut found);
    let unlisted: Vec<&String> = found
        .iter()
        .filter(|n| {
            !CORE_ENV_NAMES.contains(&n.as_str())
                && !COMPONENT_ENV_NAMES.contains(&n.as_str())
                && n.as_str() != "GRAPHITE_UNRELATED"
        })
        .collect();
    assert!(unlisted.is_empty(), "add to CORE_ENV_NAMES: {unlisted:?}");
    for name in CORE_ENV_NAMES {
        assert!(
            found.contains(*name),
            "{name} is listed and the Core never mentions it"
        );
    }
}

/// Every name another component reads is listed, so the Core never refuses
/// a variable meant for the guard, the AI layer, the dashboard or the deploy
/// kit running beside it.
#[test]
fn every_name_another_component_reads_is_listed() {
    let mut found = BTreeSet::new();
    for dir in [
        "integrations",
        "python-ai-layer",
        "sdk",
        "dashboard",
        "deploy",
        "tools",
        ".github",
        "examples",
        "docs/ops",
    ] {
        names_in(&repo().join(dir), &mut found);
    }
    for file in ["docker-compose.yml", "Dockerfile"] {
        let mut one = BTreeSet::new();
        let tmp = repo().join(file);
        if let Ok(text) = std::fs::read_to_string(&tmp) {
            for w in
                text.split(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
            {
                if w.starts_with("GRAPHITE_") && !w.ends_with('_') {
                    one.insert(w.to_string());
                }
            }
        }
        found.extend(one);
    }
    let unlisted: Vec<&String> = found
        .iter()
        .filter(|n| {
            !CORE_ENV_NAMES.contains(&n.as_str())
                && !COMPONENT_ENV_NAMES.contains(&n.as_str())
                && !n.starts_with(AI_LAYER_ENV_PREFIX)
        })
        .collect();
    assert!(
        unlisted.is_empty(),
        "add to COMPONENT_ENV_NAMES: {unlisted:?}"
    );
}

#[test]
fn a_near_miss_of_a_core_name_refuses_to_start() {
    for (typo, meant) in [
        (
            "GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWAL",
            "GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS",
        ),
        (
            "GRAPHITE_QUARANTINE_ON_UPGRADES",
            "GRAPHITE_QUARANTINE_ON_UPGRADE",
        ),
        ("GRAPHITE_RPC_WITNES_URL", "GRAPHITE_RPC_WITNESS_URL"),
        ("GRAPHITE_L8_HIGH_ASSURANCES", "GRAPHITE_L8_HIGH_ASSURANCE"),
        ("graphite_api_key", "GRAPHITE_API_KEY"),
        ("GRAPHITE_WALLET_PROFLE", "GRAPHITE_WALLET_PROFILE"),
        // Round 40 (R39-CB-8).
        ("GRAPHITE_TRUSTED_PROXIE", "GRAPHITE_TRUSTED_PROXIES"),
        ("GRAPHITE_TRUSTED_PROXYS", "GRAPHITE_TRUSTED_PROXIES"),
    ] {
        let err = check_env_names([typo]).expect_err(typo);
        assert!(
            err.contains(meant) && err.contains("REFUSING TO START"),
            "{err}"
        );
    }
}

/// Re-pinned in Round 38 (R37-15). This test pinned that an unknown
/// `GRAPHITE_*` name further than two edits from a Core name only warns
/// ("GRAPHITE_MY_DEPLOY_SCRIPT_TAG" started the server). That is how
/// `GRAPHITE_HIGH_ASSURANCE`, `GRAPHITE_AUDIT_KEY` and `GRAPHITE_WITNESS_URL`
/// — misspellings of protective switches — started a server without them.
/// Every component's names are listed, so an unknown one now refuses.
#[test]
fn known_and_unrelated_names_start() {
    let all: Vec<&str> = CORE_ENV_NAMES
        .iter()
        .chain(COMPONENT_ENV_NAMES)
        .copied()
        .collect();
    assert_eq!(check_env_names(all.iter().copied()), Ok(()));
    assert_eq!(check_env_names(["PATH", "HOME", "SOLANA_RPC_URL"]), Ok(()));
    let err = check_env_names(["GRAPHITE_MY_DEPLOY_SCRIPT_TAG", "PATH", "HOME"]).unwrap_err();
    assert!(
        err.contains("GRAPHITE_MY_DEPLOY_SCRIPT_TAG") && err.contains("REFUSING TO START"),
        "{err}"
    );
    assert_eq!(unknown_env_names(["SOLANA_RPC_URL"]), vec![]);
}

/// R37-15: the protective switches' misspellings the auditor named, each
/// more than two edits from its name, and typos in the prefix itself.
#[test]
fn a_misspelled_protective_switch_refuses_to_start_however_far_off() {
    for typo in [
        "GRAPHITE_HIGH_ASSURANCE",
        "GRAPHITE_AUDIT_KEY",
        "GRAPHITE_WITNESS_URL",
        // Round 40 (R39-CB-8): the proxy list's misspellings refuse however
        // far off; `GRAPHITE_TRUST_PROXY` with no list refuses too
        // (tests/audit_2026_10_20_startup_refusals.rs).
        "GRAPHITE_TRUSTED_PROXY_LIST",
        "GRAPHITE_PROXIES",
    ] {
        let err = check_env_names([typo]).expect_err(typo);
        assert!(
            err.contains(typo) && err.contains("REFUSING TO START"),
            "{err}"
        );
    }
    for (typo, meant) in [
        ("GRAPHTIE_AUDIT_KEY_FILE", "GRAPHITE_AUDIT_KEY_FILE"),
        ("GRAPHIT_L8_HIGH_ASSURANCE", "GRAPHITE_L8_HIGH_ASSURANCE"),
        ("GRAPHITERPC_WITNESS_URL", "GRAPHITE_RPC_WITNESS_URL"),
    ] {
        let err = check_env_names([typo]).expect_err(typo);
        assert!(
            err.contains(meant) && err.contains("REFUSING TO START"),
            "{err}"
        );
    }
}

/// The server itself refuses, before it touches the data directory.
#[cfg(feature = "server")]
#[test]
fn the_server_refuses_a_misspelled_switch() {
    let dir = std::env::temp_dir().join(format!("graphite-r36-env-{}", std::process::id()));
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_graphite"))
        .args(["server", "--port", "0"])
        .env("GRAPHITE_DATA_DIR", &dir)
        .env("GRAPHITE_DEV_MODE", "1")
        .env("GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWAL", "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    // A server that did not refuse would serve forever: bounded wait.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = std::fs::remove_dir_all(&dir);
            panic!("the server started with a misspelled switch set");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let mut stderr = String::new();
    std::io::Read::read_to_string(child.stderr.as_mut().unwrap(), &mut stderr).unwrap();
    assert!(!status.success());
    assert!(
        stderr.contains("GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS"),
        "{stderr}"
    );
    assert!(
        !dir.exists(),
        "refused before the data directory was created"
    );
}

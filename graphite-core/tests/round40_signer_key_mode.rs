//! Round 40 (R39-CB-14): `graphite registry submit` refuses a signer key file
//! that group or others can read or write, as the server refuses such an
//! audit key file.
//!
//! The signer key is a reviewer's ed25519 secret; whoever reads it signs
//! manifests that earn a trust tier. The file was read with no check, while
//! the audit key file beside it was refused at mode 0644 (Round 38, T-14).
#![cfg(feature = "cli")]

use std::path::{Path, PathBuf};
use std::process::Command;

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "graphite-r40-signer-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn key_file(dir: &Path, mode: u32) -> PathBuf {
    let path = dir.join(format!("signer-{mode:o}.key"));
    std::fs::write(&path, format!("{}\n", "7a".repeat(32))).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    path
}

/// `registry submit` with `key`, against a manifest that does not exist: a
/// key that passes is read first, and the command then fails on the manifest.
fn submit(dir: &Path, key: &Path, via_env: bool) -> (bool, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_graphite"));
    c.env_remove("GRAPHITE_SIGNER_KEY_FILE")
        .env("GRAPHITE_DATA_DIR", dir)
        .args(["registry", "submit", "--state"])
        .arg(dir.join("registry_state.json"))
        .arg("--graph-state")
        .arg(dir.join("graph_state.json"))
        .arg("--manifest")
        .arg(dir.join("no-such-manifest.json"));
    if via_env {
        c.env("GRAPHITE_SIGNER_KEY_FILE", key);
    } else {
        c.arg("--signer-key-file").arg(key);
    }
    let out = c.output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[cfg(unix)]
#[test]
fn a_signer_key_file_others_can_read_is_refused() {
    let dir = temp_dir("refuse");
    for mode in [0o644, 0o640, 0o604, 0o602, 0o660, 0o666] {
        let key = key_file(&dir, mode);
        for via_env in [false, true] {
            let (ok, err) = submit(&dir, &key, via_env);
            assert!(!ok, "mode {mode:o} (env {via_env}): {err}");
            assert!(
                err.contains("readable or writable by group or others")
                    && err.contains(&format!("mode {mode:03o}"))
                    && err.contains("chmod 600"),
                "mode {mode:o} (env {via_env}): {err}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_signer_key_file_only_its_owner_can_read_is_read() {
    let dir = temp_dir("accept");
    for mode in [0o600, 0o400] {
        let key = key_file(&dir, mode);
        assert_eq!(
            graphite_core::cli::read_signer_key_file(&key).unwrap(),
            "7a".repeat(32),
            "the contents, trimmed"
        );
        for via_env in [false, true] {
            let (ok, err) = submit(&dir, &key, via_env);
            assert!(!ok, "the manifest does not exist");
            assert!(
                !err.contains("signer key file"),
                "mode {mode:o} (env {via_env}): the key was refused: {err}"
            );
            // ...and the command went on to the manifest, which is absent.
            assert!(err.contains("NotFound"), "{err}");
        }
    }
    // Not a file, and no file: refused, naming it.
    let e = graphite_core::cli::read_signer_key_file(&dir).unwrap_err();
    assert!(e.contains("is not a file"), "{e}");
    let e = graphite_core::cli::read_signer_key_file(&dir.join("absent.key")).unwrap_err();
    assert!(e.contains("failed to read signer key file"), "{e}");
    let _ = std::fs::remove_dir_all(&dir);
}

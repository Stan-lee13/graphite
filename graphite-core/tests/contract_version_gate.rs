//! Constitution P13: the published contract breaks only with a version bump
//! and a CHANGELOG entry that names what broke (roadmap R-M2, Round 28).
//!
//! The contract is the two published schemas: `verification-result-v1.json`,
//! which Graphite writes and a consumer reads, and `proposed-intent-v1.json`,
//! which a caller writes and Graphite reads. `verification_result_schema_contract.rs`
//! already holds every emitted field to the schema, so the schema is the
//! surface.
//!
//! The gate compares each schema with the same file as last released. A
//! change breaks the contract when a client written against the release
//! stops working, so the rule depends on who writes the document:
//!
//! - **Output** (Graphite writes it): removing a field, widening a type or
//!   an enum, dropping a required field, loosening a bound, opening a closed
//!   object, or adding a field to a closed one.
//! - **Input** (the caller writes it): removing a field, narrowing a type or
//!   an enum, requiring a field, tightening a bound, or closing an object.
//!
//! When anything breaks, the crate's version must differ from the tag's, and
//! the CHANGELOG's section for the crate's version must name every broken
//! path. Descriptions and titles are not part of the surface.
//!
//! The released schemas are a committed snapshot,
//! `tests/fixtures/contract/<tag>/`, byte for byte the files at the release
//! tag `RELEASED` and pinned here by SHA-256. Round 29 (audit 2026-10-20,
//! C3): the gate used to read the tag with `git` at test time, and without
//! the history — a source tarball, a shallow clone, which is what this very
//! audit ran in — it printed "CONTRACT GATE NOT RUN" and passed, so every
//! test count that included it counted a gate that had not run. The
//! comparison now runs everywhere, from the snapshot.
//!
//! Where `git` and the tags ARE available, two more checks run: the
//! snapshot must be byte-identical to the tag's files (so it cannot be
//! edited to hide a break — the SHA-256 pins catch that without git too),
//! and no release tag may be newer than the snapshot (a release must move
//! the snapshot with it). CI fetches the tags and sets
//! `GRAPHITE_CONTRACT_GATE_REQUIRED=1`, which makes those two checks
//! mandatory there instead of best-effort.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    /// Graphite writes the document.
    Output,
    /// The caller writes it.
    Input,
}

const SCHEMAS: &[(&str, Direction)] = &[
    ("verification-result-v1.json", Direction::Output),
    ("proposed-intent-v1.json", Direction::Input),
];

/// One node of a schema: what a client depends on at that path.
#[derive(Clone, Debug, Default, PartialEq)]
struct Node {
    types: Option<BTreeSet<String>>,
    /// `enum`, or a `const` as a one-value enum.
    values: Option<BTreeSet<String>>,
    required: bool,
    closed: bool,
    minimum: Option<f64>,
    maximum: Option<f64>,
    min_length: Option<u64>,
    min_items: Option<u64>,
    pattern: Option<String>,
}

/// Every node of a schema by path: `a.b`, `a[]` for items, `a<oneOf0>` for
/// a branch, `a{*}` for a typed `additionalProperties`, `$` for the root.
fn surface(schema: &Value) -> BTreeMap<String, Node> {
    fn walk(s: &Value, path: String, required: bool, out: &mut BTreeMap<String, Node>) {
        let Some(obj) = s.as_object() else {
            return;
        };
        let set = |v: &Value| -> BTreeSet<String> {
            match v {
                Value::Array(a) => a.iter().map(|x| x.to_string()).collect(),
                other => std::iter::once(other.to_string()).collect(),
            }
        };
        let node = Node {
            types: obj.get("type").map(|t| match t {
                Value::Array(a) => a
                    .iter()
                    .map(|x| x.as_str().unwrap_or("?").to_string())
                    .collect(),
                other => std::iter::once(other.as_str().unwrap_or("?").to_string()).collect(),
            }),
            values: obj.get("enum").map(set).or_else(|| {
                obj.get("const")
                    .map(|c| std::iter::once(c.to_string()).collect())
            }),
            required,
            closed: obj.get("additionalProperties") == Some(&Value::Bool(false)),
            minimum: obj.get("minimum").and_then(Value::as_f64),
            maximum: obj.get("maximum").and_then(Value::as_f64),
            min_length: obj.get("minLength").and_then(Value::as_u64),
            min_items: obj.get("minItems").and_then(Value::as_u64),
            pattern: obj.get("pattern").and_then(Value::as_str).map(String::from),
        };
        let here = if path.is_empty() {
            "$".to_string()
        } else {
            path.clone()
        };
        out.insert(here, node);
        let req: BTreeSet<&str> = obj
            .get("required")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if let Some(props) = obj.get("properties").and_then(Value::as_object) {
            for (name, sub) in props {
                let child = if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}.{name}")
                };
                walk(sub, child, req.contains(name.as_str()), out);
            }
        }
        if let Some(items) = obj.get("items") {
            walk(items, format!("{path}[]"), false, out);
        }
        if let Some(branches) = obj.get("oneOf").and_then(Value::as_array) {
            for (i, b) in branches.iter().enumerate() {
                walk(b, format!("{path}<oneOf{i}>"), false, out);
            }
        }
        if let Some(extra @ Value::Object(_)) = obj.get("additionalProperties") {
            walk(extra, format!("{path}{{*}}"), false, out);
        }
    }
    let mut out = BTreeMap::new();
    walk(schema, String::new(), false, &mut out);
    out
}

/// The parent path of a node, if it has one.
fn parent(path: &str) -> Option<&str> {
    if path == "$" {
        return None;
    }
    let cut = path.rfind(['.', '[', '<', '{']).unwrap_or(0);
    Some(if cut == 0 { "$" } else { &path[..cut] })
}

/// Whether `new` accepts everything `old` accepts (`None` is "anything").
fn widens<T: Ord>(old: &Option<BTreeSet<T>>, new: &Option<BTreeSet<T>>) -> bool {
    match (old, new) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(o), Some(n)) => o.is_subset(n),
    }
}

/// Whether a lower bound moved down or went away (looser).
fn lower_loosens<T: PartialOrd>(old: &Option<T>, new: &Option<T>) -> bool {
    match (old, new) {
        (Some(_), None) => true,
        (Some(o), Some(n)) => n < o,
        _ => false,
    }
}

/// Whether a lower bound appeared or moved up (tighter).
fn lower_tightens<T: PartialOrd>(old: &Option<T>, new: &Option<T>) -> bool {
    match (old, new) {
        (None, Some(_)) => true,
        (Some(o), Some(n)) => n > o,
        _ => false,
    }
}

/// Whether an upper bound moved up or went away (looser).
fn upper_loosens<T: PartialOrd>(old: &Option<T>, new: &Option<T>) -> bool {
    match (old, new) {
        (Some(_), None) => true,
        (Some(o), Some(n)) => n > o,
        _ => false,
    }
}

/// Whether an upper bound appeared or moved down (tighter).
fn upper_tightens<T: PartialOrd>(old: &Option<T>, new: &Option<T>) -> bool {
    match (old, new) {
        (None, Some(_)) => true,
        (Some(o), Some(n)) => n < o,
        _ => false,
    }
}

/// What breaks between two versions of one schema, by path and reason.
fn breaking(old: &Value, new: &Value, direction: Direction) -> Vec<(String, String)> {
    let (old, new) = (surface(old), surface(new));
    let mut out = Vec::new();
    for (path, o) in &old {
        let Some(n) = new.get(path) else {
            out.push((path.clone(), "removed".to_string()));
            continue;
        };
        let mut why = Vec::new();
        match direction {
            Direction::Output => {
                if !widens(&n.types, &o.types) {
                    why.push("type widened");
                }
                if !widens(&n.values, &o.values) {
                    why.push("values widened");
                }
                if o.required && !n.required {
                    why.push("no longer required");
                }
                if o.closed && !n.closed {
                    why.push("opened");
                }
                if lower_loosens(&o.minimum, &n.minimum)
                    || lower_loosens(&o.min_length, &n.min_length)
                    || lower_loosens(&o.min_items, &n.min_items)
                    || upper_loosens(&o.maximum, &n.maximum)
                {
                    why.push("bound loosened");
                }
            }
            Direction::Input => {
                if !widens(&o.types, &n.types) {
                    why.push("type narrowed");
                }
                if !widens(&o.values, &n.values) {
                    why.push("values narrowed");
                }
                if n.required && !o.required {
                    why.push("now required");
                }
                if n.closed && !o.closed {
                    why.push("closed");
                }
                if lower_tightens(&o.minimum, &n.minimum)
                    || lower_tightens(&o.min_length, &n.min_length)
                    || lower_tightens(&o.min_items, &n.min_items)
                    || upper_tightens(&o.maximum, &n.maximum)
                {
                    why.push("bound tightened");
                }
            }
        }
        if o.pattern != n.pattern {
            why.push("pattern changed");
        }
        if !why.is_empty() {
            out.push((path.clone(), why.join(", ")));
        }
    }
    for (path, n) in &new {
        if old.contains_key(path) {
            continue;
        }
        let parent_closed = parent(path)
            .and_then(|p| old.get(p))
            .is_some_and(|p| p.closed);
        match direction {
            Direction::Output if parent_closed => {
                out.push((path.clone(), "added to a closed object".to_string()))
            }
            Direction::Input if n.required && old.contains_key(parent(path).unwrap_or("$")) => {
                out.push((path.clone(), "added as required".to_string()))
            }
            _ => {}
        }
    }
    out
}

/// The last release, whose schemas are the contract.
const RELEASED: &str = "v0.2.0-beta";

/// SHA-256 of each snapshot file, as fetched from `RELEASED`
/// (commit 39c501604864dae8002e1ef0769af34e41c42f94; git blobs
/// ac20443e1e8e4bd5faaf863a09445da6bfbf282f and
/// d98876a48a7be25c5a7aae13f00d7d76a13d5267).
const RELEASED_SHA256: &[(&str, &str)] = &[
    (
        "verification-result-v1.json",
        "084b11ff36b45a343193bde3cd5f1f2116637aeb6eea9d2d494a8128113cd1bf",
    ),
    (
        "proposed-intent-v1.json",
        "a07db3ee45a03aa999520d8aabae2d84a18cae695fcbd149fe31c5c55bed5f13",
    ),
];

fn snapshot_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("contract")
        .join(RELEASED)
}

/// The released schema `file`, from the committed snapshot, after checking
/// it against its pinned hash.
fn released_schema(file: &str) -> Option<String> {
    let pinned = RELEASED_SHA256.iter().find(|(f, _)| *f == file)?.1;
    let text = std::fs::read_to_string(snapshot_dir().join(file)).unwrap_or_else(|e| {
        panic!(
            "the released contract snapshot {} is missing: {e}",
            snapshot_dir().join(file).display()
        )
    });
    use sha2::Digest;
    let actual = hex::encode(sha2::Sha256::digest(text.as_bytes()));
    assert_eq!(
        actual, pinned,
        "the committed snapshot of {RELEASED}:schemas/{file} was edited; it must stay \
         byte-identical to the release"
    );
    Some(text)
}

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("graphite-core sits in the repository")
}

fn git(args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(repo_root())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The CHANGELOG's section for `version`: from its `## [<version>` heading
/// to the next `## ` heading.
fn changelog_section<'a>(changelog: &'a str, version: &str) -> Option<&'a str> {
    let heading = format!("## [{version}]");
    let start = changelog.find(&heading)?;
    let rest = &changelog[start + heading.len()..];
    let end = rest.find("\n## ").unwrap_or(rest.len());
    Some(&rest[..end])
}

/// The gate itself: every schema against the released snapshot.
#[test]
fn the_contract_breaks_only_with_a_version_bump_and_a_changelog_entry() {
    let version = env!("CARGO_PKG_VERSION");
    let changelog = include_str!("../CHANGELOG.md");
    let mut broken = Vec::new();
    for (file, direction) in SCHEMAS {
        let Some(old) = released_schema(file) else {
            // A schema first published after the release has no prior
            // contract (and no snapshot entry).
            continue;
        };
        let old: Value = serde_json::from_str(&old).expect("the released schema is JSON");
        let new: Value = serde_json::from_str(
            &std::fs::read_to_string(repo_root().join("schemas").join(file)).unwrap(),
        )
        .unwrap();
        for (path, why) in breaking(&old, &new, *direction) {
            broken.push((format!("{file}:{path}"), why));
        }
    }
    if broken.is_empty() {
        return;
    }
    let listed: Vec<String> = broken.iter().map(|(p, w)| format!("{p} ({w})")).collect();
    let released = RELEASED.trim_start_matches('v');
    assert_ne!(
        version,
        released,
        "the contract broke since {RELEASED} without a version bump:\n  {}",
        listed.join("\n  ")
    );
    let section = changelog_section(changelog, version).unwrap_or_else(|| {
        panic!(
            "the contract broke since {RELEASED}; CHANGELOG.md needs a `## [{version}]` section naming:\n  {}",
            listed.join("\n  ")
        )
    });
    let unnamed: Vec<&String> = broken
        .iter()
        .zip(&listed)
        .filter(|((path, _), _)| !section.contains(path.as_str()))
        .map(|(_, l)| l)
        .collect();
    assert!(
        unnamed.is_empty(),
        "the `## [{version}]` CHANGELOG section must name every break since {RELEASED}; missing:\n  {}",
        unnamed
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

/// The snapshot is the release: byte-identical to the tag's files, and no
/// release is newer than it. Needs the tags; best-effort without them,
/// mandatory where `GRAPHITE_CONTRACT_GATE_REQUIRED=1` (CI).
#[test]
fn the_contract_snapshot_is_the_last_release() {
    let required = std::env::var("GRAPHITE_CONTRACT_GATE_REQUIRED").as_deref() == Ok("1");
    if git(&[
        "rev-parse",
        "--verify",
        "--quiet",
        &format!("{RELEASED}^{{commit}}"),
    ])
    .is_none()
    {
        assert!(
            !required,
            "GRAPHITE_CONTRACT_GATE_REQUIRED=1 but tag {RELEASED} is not reachable \
             (fetch the tags: fetch-depth: 0)"
        );
        // The comparison itself ran from the snapshot, pinned by SHA-256;
        // only the provenance cross-check needs the tag.
        eprintln!(
            "contract snapshot provenance not cross-checked: tag {RELEASED} is not reachable here"
        );
        return;
    }
    for (file, _) in RELEASED_SHA256 {
        let at_tag = git(&["show", &format!("{RELEASED}:schemas/{file}")])
            .unwrap_or_else(|| panic!("{RELEASED} has no schemas/{file}"));
        let snapshot = released_schema(file).unwrap();
        // `git` output is trimmed; compare the documents' bytes the same way.
        assert_eq!(
            snapshot.trim_end(),
            at_tag,
            "tests/fixtures/contract/{RELEASED}/{file} differs from {RELEASED}:schemas/{file}"
        );
    }
    // A newer release tag means the contract moved; the snapshot must move
    // with it, or every later break is judged against a stale release.
    if let Some(latest) = git(&["describe", "--tags", "--abbrev=0", "--match", "v*"]) {
        if latest != RELEASED {
            let newer = git(&["merge-base", "--is-ancestor", RELEASED, &latest]).is_some();
            assert!(
                !newer,
                "release {latest} is newer than the committed contract snapshot ({RELEASED}): \
                 snapshot its schemas into tests/fixtures/contract/{latest}/ and update RELEASED \
                 and RELEASED_SHA256"
            );
        }
    }
}

/// The rules, on schemas written for the purpose, so the gate's judgement
/// is tested on its own.
#[test]
fn the_breaking_rules_follow_who_writes_the_document() {
    let base = serde_json::json!({
        "type": "object",
        "required": ["a"],
        "properties": {
            "a": {"type": "string", "enum": ["x", "y"]},
            "b": {"type": ["string", "null"]},
            "n": {"type": "integer", "minimum": 1},
            "o": {"type": "object", "properties": {"p": {"type": "string"}}},
            "c": {
                "type": "object",
                "additionalProperties": false,
                "properties": {"q": {"type": "string"}}
            }
        }
    });
    let changed = |edit: &dyn Fn(&mut Value)| {
        let mut v = base.clone();
        edit(&mut v);
        v
    };
    let paths = |old: &Value, new: &Value, d: Direction| -> Vec<String> {
        breaking(old, new, d).into_iter().map(|(p, _)| p).collect()
    };
    let none: Vec<String> = Vec::new();

    // Unchanged, and a description edit: nothing breaks either way.
    let described = changed(&|v| v["properties"]["a"]["description"] = "now documented".into());
    for d in [Direction::Output, Direction::Input] {
        assert_eq!(paths(&base, &base, d), none);
        assert_eq!(paths(&base, &described, d), none);
    }

    // Removing a field breaks both.
    let removed = changed(&|v| {
        v["properties"].as_object_mut().unwrap().remove("b");
    });
    assert_eq!(paths(&base, &removed, Direction::Output), vec!["b"]);
    assert_eq!(paths(&base, &removed, Direction::Input), vec!["b"]);

    // An enum gaining a value breaks an output, not an input; losing one,
    // the other way round.
    let gained = changed(&|v| v["properties"]["a"]["enum"] = serde_json::json!(["x", "y", "z"]));
    assert_eq!(paths(&base, &gained, Direction::Output), vec!["a"]);
    assert_eq!(paths(&base, &gained, Direction::Input), none);
    let lost = changed(&|v| v["properties"]["a"]["enum"] = serde_json::json!(["x"]));
    assert_eq!(paths(&base, &lost, Direction::Output), none);
    assert_eq!(paths(&base, &lost, Direction::Input), vec!["a"]);

    // Narrowing a type (string|null to string) is safe for an output only.
    let narrowed = changed(&|v| v["properties"]["b"]["type"] = "string".into());
    assert_eq!(paths(&base, &narrowed, Direction::Output), none);
    assert_eq!(paths(&base, &narrowed, Direction::Input), vec!["b"]);

    // Requiring a field breaks an input; no longer requiring one breaks an
    // output.
    let requires_b = changed(&|v| v["required"] = serde_json::json!(["a", "b"]));
    assert_eq!(paths(&base, &requires_b, Direction::Output), none);
    assert_eq!(paths(&base, &requires_b, Direction::Input), vec!["b"]);
    let drops_a = changed(&|v| v["required"] = serde_json::json!([]));
    assert_eq!(paths(&base, &drops_a, Direction::Output), vec!["a"]);
    assert_eq!(paths(&base, &drops_a, Direction::Input), none);

    // Closing an object breaks an input; opening one breaks an output; a
    // field added to a closed output object breaks it.
    let closes_o = changed(&|v| v["properties"]["o"]["additionalProperties"] = false.into());
    assert_eq!(paths(&base, &closes_o, Direction::Output), none);
    assert_eq!(paths(&base, &closes_o, Direction::Input), vec!["o"]);
    let opens_c = changed(&|v| {
        v["properties"]["c"]
            .as_object_mut()
            .unwrap()
            .remove("additionalProperties");
    });
    assert_eq!(paths(&base, &opens_c, Direction::Output), vec!["c"]);
    assert_eq!(paths(&base, &opens_c, Direction::Input), none);
    let adds_to_c = changed(&|v| {
        v["properties"]["c"]["properties"]["r"] = serde_json::json!({"type": "string"})
    });
    assert_eq!(paths(&base, &adds_to_c, Direction::Output), vec!["c.r"]);
    assert_eq!(paths(&base, &adds_to_c, Direction::Input), none);

    // A new optional field is safe both ways; a new required one breaks an
    // input.
    let adds_d = changed(&|v| v["properties"]["d"] = serde_json::json!({"type": "string"}));
    assert_eq!(paths(&base, &adds_d, Direction::Output), none);
    assert_eq!(paths(&base, &adds_d, Direction::Input), none);
    let adds_required_d = changed(&|v| {
        v["properties"]["d"] = serde_json::json!({"type": "string"});
        v["required"] = serde_json::json!(["a", "d"]);
    });
    assert_eq!(paths(&base, &adds_required_d, Direction::Input), vec!["d"]);

    // A bound: raising a minimum breaks an input, lowering it an output.
    let raised = changed(&|v| v["properties"]["n"]["minimum"] = 2.into());
    assert_eq!(paths(&base, &raised, Direction::Output), none);
    assert_eq!(paths(&base, &raised, Direction::Input), vec!["n"]);
    let lowered = changed(&|v| v["properties"]["n"]["minimum"] = 0.into());
    assert_eq!(paths(&base, &lowered, Direction::Output), vec!["n"]);
    assert_eq!(paths(&base, &lowered, Direction::Input), none);
}

/// The CHANGELOG section reader stops at the next heading, so a path named
/// in another version's section does not count for this one.
#[test]
fn a_break_must_be_named_in_its_own_version_section() {
    let changelog = "# Changelog\n\n## [0.9.0] — next\n\n- `x.json:a` removed\n\n## [Round 1]\n\n- `x.json:b`\n";
    let section = changelog_section(changelog, "0.9.0").unwrap();
    assert!(section.contains("x.json:a"));
    assert!(!section.contains("x.json:b"));
    assert!(changelog_section(changelog, "0.8.0").is_none());
}

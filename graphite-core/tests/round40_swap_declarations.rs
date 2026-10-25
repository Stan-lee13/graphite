//! Round 40 (manifests workstream): the swap and route declarations rewritten
//! from the committed IDLs (R39-CORE-DECISION-4), and the instructions no
//! committed IDL has, removed (R39-SUPPLY-CHAIN-11), held to their record,
//! `docs/audit-r40/declaration-rewrites.json`, with the real parser.
//!
//! The end-to-end evidence (honest swaps executable, skims refused) is in
//! `tests/round39_decision_campaigns.rs`
//! (`round39_honest_pool_swaps_and_the_declarations_that_refuse_them`,
//! `round40_a_rewritten_pool_swap_with_a_skim_is_never_executable`); this
//! file proves, for every rewritten row, what its declaration excuses and
//! that it says only what the cited IDL instruction's accounts say.

use graphite_core::manifest::{load_seed_manifests, InstructionDef};
use graphite_core::state_diff::{security_class_line, DeclaredEffects};
use graphite_core::verification::GraphiteCore;
use serde_json::Value;

fn record() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../docs/audit-r40/declaration-rewrites.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("the Round 40 record")).unwrap()
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect()
}

fn norm(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_lowercase()
}

/// The IDL instruction's accounts, nested groups flattened: (name, writable,
/// signer).
fn idl_accounts(file: &str, name: &str) -> Vec<(String, bool, bool)> {
    let path = format!("{}/../{file}", env!("CARGO_MANIFEST_DIR"));
    let idl: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let ix = idl["instructions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("{file} has no {name}"));
    fn walk(accs: &Value, out: &mut Vec<(String, bool, bool)>) {
        for a in accs.as_array().unwrap() {
            if a.get("accounts").is_some() {
                walk(&a["accounts"], out);
            } else {
                let flag = |k: &str, legacy: &str| {
                    a.get(k)
                        .or_else(|| a.get(legacy))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                };
                out.push((
                    a["name"].as_str().unwrap().to_string(),
                    flag("writable", "isMut"),
                    flag("signer", "isSigner"),
                ));
            }
        }
    }
    let mut out = Vec::new();
    walk(&ix["accounts"], &mut out);
    out
}

fn instruction(program: &str, name: &str) -> InstructionDef {
    load_seed_manifests()
        .get(program)
        .unwrap_or_else(|| panic!("{program} has a seed manifest"))
        .instructions
        .iter()
        .find(|i| i.name == name)
        .unwrap_or_else(|| panic!("{program} declares {name}"))
        .clone()
}

fn parsed(ix: &InstructionDef, lines: &[String]) -> DeclaredEffects {
    let mut with_class = lines.to_vec();
    with_class.push(security_class_line(ix.security_class()));
    DeclaredEffects::parse(&with_class)
}

/// Every rewritten declaration is the manifest's, is read in full, names an
/// account for every effect of every added line, excuses a debit of exactly
/// the accounts its record lists (no other account of any layout — the
/// user's output among them, except where the IDL's direction argument makes
/// it the input), names only writable non-signing accounts of the cited IDL
/// instruction, and still passes L5 for a swap intent and L7 Check 8.
#[test]
fn every_round40_rewrite_excuses_exactly_the_debits_its_idl_names() {
    let rec = record();
    let rows = rec["rewrites"].as_array().unwrap();
    assert_eq!(rows.len(), 60, "the Round 40 rewrites");
    let mut wrong = Vec::new();
    for r in rows {
        let program = r["program_id"].as_str().unwrap();
        let name = r["instruction"].as_str().unwrap();
        let w = format!("{program}::{name}");
        let ix = instruction(program, name);
        let new = strings(&r["new_lines"]);
        if ix.expected_state_changes != new {
            wrong.push(format!("{w}: the manifest is not the record's new_lines"));
            continue;
        }
        // L4's no-diff structural check (`verify_state`) reads the words
        // "debit"/"credit": a rewrite that dropped them would switch it off
        // (the attack fixtures `test_novel_cross_prog_012/017` and
        // `test_real_fake_swap_045` rely on it for Orca `swap`).
        let words = |ls: &[String]| {
            ls.iter().any(|l| {
                let l = l.to_lowercase();
                l.contains("debit") || l.contains("credit")
            })
        };
        if words(&strings(&r["old_lines"])) && !words(&new) {
            wrong.push(format!(
                "{w}: the debit/credit words L4's structural check reads are gone"
            ));
        }
        let e = parsed(&ix, &new);
        if !e.is_interpretable() || !e.debit || !e.credit || e.debit_names_no_account() {
            wrong.push(format!(
                "{w}: the declaration is not a read, scoped debit and credit"
            ));
        }
        for line in strings(&r["added"]) {
            let one = DeclaredEffects::parse(std::slice::from_ref(&line));
            if one.unrecognised
                || one.debit_names_no_account()
                || !(one.debit || one.credit || one.mint || one.burn)
            {
                wrong.push(format!(
                    "{w}: added line not read as a scoped effect: {line}"
                ));
            }
            if one.authority || one.delegate || one.close || one.create || one.freeze {
                wrong.push(format!("{w}: added line declares an authority, delegate, close, create or freeze: {line}"));
            }
        }
        // Exactly the record's debit-named accounts, over every layout name.
        let debit_named = strings(&r["debit_named"]);
        let mut names: Vec<String> = Vec::new();
        for lay in std::iter::once(&ix.accounts).chain(ix.account_layouts.iter()) {
            for a in lay {
                if !names.contains(&a.name) {
                    names.push(a.name.clone());
                }
            }
        }
        for n in &names {
            if e.covers_by_name("debit", &[n.as_str()]) != debit_named.contains(n) {
                wrong.push(format!(
                    "{w}: debit of `{n}` excused={}, record says {}",
                    e.covers_by_name("debit", &[n.as_str()]),
                    debit_named.contains(n)
                ));
            }
        }
        // Named accounts: in every layout; writable, not a signer, in the IDL.
        let idl_file = r["idl_source"].as_str().unwrap().split(' ').next().unwrap();
        let idl = idl_accounts(idl_file, r["idl_instruction"].as_str().unwrap());
        for (k, a) in ix.accounts.iter().enumerate() {
            if idl.get(k).map(|x| norm(&x.0)) != Some(norm(&a.name)) {
                wrong.push(format!(
                    "{w}: layout slot {k} `{}` is not the IDL's",
                    a.name
                ));
                break;
            }
        }
        for line in &new {
            for (i, _) in line.match_indices("accounts.") {
                let reference: String = line[i + 9..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                for lay in std::iter::once(&ix.accounts).chain(ix.account_layouts.iter()) {
                    if !lay.iter().any(|a| a.name == reference) {
                        wrong.push(format!("{w}: `{reference}` is not in every layout"));
                    }
                }
                match idl.iter().find(|x| norm(&x.0) == norm(&reference)) {
                    Some((_, true, false)) => {}
                    other => wrong.push(format!("{w}: `{reference}` in the IDL: {other:?}")),
                }
            }
        }
        if let Err(why) = GraphiteCore::intent_describes_instruction(
            "swap",
            program,
            name,
            ix.security_class(),
            &new,
        ) {
            wrong.push(format!("{w}: L5 refuses a swap intent: {why}"));
        }
        if graphite_core::risk_engine::detect_fake_swap(program, &[], &new, "swap", None).is_some()
        {
            wrong.push(format!("{w}: L7 Check 8 (FakeSwap) fires"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// The input account each venue class debits is named, and the output
/// account is not, except where the IDL's own direction argument makes
/// either account the input (Orca's `a_to_b`).
#[test]
fn the_rewrites_name_the_input_and_never_the_output_alone() {
    for (program, name, input, output, both) in [
        (
            "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C",
            "swap_base_input",
            "input_token_account",
            "output_token_account",
            false,
        ),
        (
            "cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG",
            "swap",
            "input_token_account",
            "output_token_account",
            false,
        ),
        (
            "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
            "exactOutRoute",
            "user_source_token_account",
            "user_destination_token_account",
            false,
        ),
        (
            "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo",
            "swap_exact_out",
            "user_token_in",
            "user_token_out",
            false,
        ),
        (
            "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",
            "swap",
            "token_owner_account_a",
            "token_owner_account_b",
            true,
        ),
        (
            "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",
            "swapV2",
            "token_owner_account_a",
            "token_owner_account_b",
            true,
        ),
        (
            "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",
            "twoHopSwapV2",
            "token_owner_account_input",
            "token_owner_account_output",
            false,
        ),
    ] {
        let ix = instruction(program, name);
        let e = parsed(&ix, &ix.expected_state_changes);
        assert!(
            e.covers_by_name("debit", &[input]),
            "{name}: the input `{input}` is not named"
        );
        assert_eq!(
            e.covers_by_name("debit", &[output]),
            both,
            "{name}: `{output}`"
        );
        assert!(
            e.covers_by_name("credit", &[output]),
            "{name}: the output `{output}` is not credited"
        );
    }
}

/// The declarations left unchanged still say what their record says (a debit
/// naming no account), and the removed instructions are gone.
#[test]
fn the_unchanged_rows_and_the_removed_instructions_are_as_recorded() {
    let rec = record();
    let reg = load_seed_manifests();
    let left = rec["left_unchanged"].as_object().unwrap();
    assert_eq!(left.len(), 26);
    for (key, v) in left {
        let program = v["program_id"].as_str().unwrap();
        let name = key.split("::").nth(1).unwrap();
        let ix = instruction(program, name);
        assert_eq!(ix.expected_state_changes, strings(&v["lines"]), "{key}");
        assert!(
            parsed(&ix, &ix.expected_state_changes).debit_names_no_account(),
            "{key}"
        );
    }
    let removed = rec["removed_instructions"].as_array().unwrap();
    assert_eq!(removed.len(), 23);
    for x in removed {
        let file = x["manifest"].as_str().unwrap();
        let program = match file {
            "graphite-core/protocols/jupiter-v6.json" => {
                "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
            }
            "graphite-core/protocols/meteora-dlmm.json" => {
                "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo"
            }
            other => panic!("an instruction removed from {other}"),
        };
        let (name, disc) = (
            x["instruction"].as_str().unwrap(),
            x["discriminator"].as_str().unwrap(),
        );
        let m = reg.get(program).unwrap();
        assert!(
            !m.instructions
                .iter()
                .any(|i| i.name == name || i.discriminator == disc),
            "{file}: {name} ({disc}) is still declared"
        );
    }
}

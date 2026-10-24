//! Round 30 (roadmap R-M13 / R-M14): honest intents for withdrawals, fee
//! claims, protocol position closes, burns and owner configuration — each
//! granted per instruction and grounded in the transaction's own accounts
//! (`intent_grants`), never by class.
//!
//! Before this round every one of these was refused under any intent (R2: no
//! intent declared the class). The tests below show both directions on the
//! running pipeline:
//!
//! - the granted instruction, with its proceeds going to the signer's own
//!   associated token accounts (or its rent to the signer, or its object
//!   seeded by the signer), passes L5 and the Risk Engine's intent checks
//!   under its intent;
//! - the same instruction with ONE account pointed elsewhere is refused, and
//!   the refusal names the fact that failed;
//! - the new intents declare nothing else: not a transfer to a stranger, not
//!   an ungranted withdrawal, not an authority change, not a mint, not each
//!   other's instructions; and a granted instruction with no intent is still
//!   refused (Check 10).

use graphite_core::find_program_address;
use graphite_core::manifest::{load_seed_manifests, InstructionDef};
use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::solana_types::Pubkey;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, ProposedIntent, VerificationInput, VerificationResult,
};

const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const SYSTEM: &str = "11111111111111111111111111111111";
const DLMM: &str = "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo";
const CLMM: &str = "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK";
const PUMP_AMM: &str = "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA";
const MARKETPLACE: &str = "CcmRKTuZCGJBWQwMHvDYApBRvSZNHqGJXkznqpDTSQUr";
const MMM: &str = "mmm3XBJg5gk8XJxEKBvdgptZz6SgK4tXvn36sodowMc";
const KAMINO_VAULT: &str = "KvauGMspG5k6rtzrqqn7WNn3oZdyKqLKwK2XWQ8FLjd";

/// The wallet that signs: owner of the position, the offer, the tokens.
const OWNER: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
/// Somebody else.
const STRANGER: &str = "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7";

fn pk(s: &str) -> Pubkey {
    Pubkey::from_base58(s).unwrap()
}

fn ata(owner: &str, mint: &str) -> String {
    find_program_address(
        &[
            pk(owner).as_bytes(),
            pk(TOKEN).as_bytes(),
            pk(mint).as_bytes(),
        ],
        &pk(ATA_PROGRAM),
    )
    .unwrap()
    .0
    .to_base58()
}

/// A distinct valid key per slot.
fn filler(i: usize) -> String {
    let mut key = [0u8; 32];
    key[0] = 0x5A;
    key[1..9].copy_from_slice(&(i as u64 + 1).to_le_bytes());
    bs58::encode(key).into_string()
}

fn def(program: &str, name: &str) -> InstructionDef {
    load_seed_manifests()
        .get(program)
        .unwrap_or_else(|| panic!("{program} has a seed manifest"))
        .instructions
        .iter()
        .find(|i| i.name == name)
        .unwrap_or_else(|| panic!("{program} declares {name}"))
        .clone()
}

/// An account list for `name` that satisfies its layout's fixed addresses
/// and PDA seeds, with `set` applied (role → key) before the PDAs are
/// derived, so a seed that names an account uses the value set here.
fn accounts_for(program: &str, d: &InstructionDef, set: &[(&str, String)]) -> Vec<String> {
    let mut keys: Vec<String> = d
        .accounts
        .iter()
        .enumerate()
        .map(|(i, _)| filler(i))
        .collect();
    for (i, a) in d.accounts.iter().enumerate() {
        if let Some((_, v)) = set.iter().find(|(r, _)| *r == a.name) {
            keys[i] = v.clone();
        } else if let Some(first) = a.expected_address.first() {
            keys[i] = if first == "{program_id}" {
                program.to_string()
            } else {
                first.clone()
            };
        }
    }
    for (i, a) in d.accounts.iter().enumerate() {
        if a.pda_seeds.is_empty() {
            continue;
        }
        let seeds: Vec<Vec<u8>> = a
            .pda_seeds
            .iter()
            .map(|s| {
                match s
                    .strip_prefix("{account_")
                    .and_then(|r| r.strip_suffix('}'))
                {
                    Some(n) => pk(&keys[n.parse::<usize>().unwrap()]).as_bytes().to_vec(),
                    None if s == "{program_id}" => pk(program).as_bytes().to_vec(),
                    None => s.as_bytes().to_vec(),
                }
            })
            .collect();
        let refs: Vec<&[u8]> = seeds.iter().map(|s| s.as_slice()).collect();
        keys[i] = find_program_address(&refs, &pk(program))
            .unwrap()
            .0
            .to_base58();
    }
    keys
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2 * 2)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// A request with arguments of 1-bytes: 32 of them, enough for the longest
/// granted instruction's minimum outputs (Raydium CLMM
/// `decrease_liquidity_v2`: liquidity u128, then two u64 minimums, Round 32),
/// so every minimum output reads as non-zero.
fn request(
    program: &str,
    d: &InstructionDef,
    accounts: Vec<String>,
    intent: &str,
) -> VerificationInput {
    request_with_args(program, d, accounts, intent, &[1u8; 32])
}

/// A request whose instruction data is the discriminator and then `args`.
fn request_with_args(
    program: &str,
    d: &InstructionDef,
    accounts: Vec<String>,
    intent: &str,
    args: &[u8],
) -> VerificationInput {
    let mut data = hex_to_bytes(&d.discriminator);
    data.extend_from_slice(args);
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: intent.to_string(),
            raw_natural_language: format!("{intent} please"),
            confidence_of_parse: 1.0,
            extracted_parameters: None,
        },
        program_id: program.to_string(),
        protocol_version: String::new(),
        instruction_discriminator: d.discriminator.clone(),
        account_addresses: accounts,
        instruction_data: Some(data),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        real_account_metas: vec![],
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        state_diff: None,
    }
}

fn verify(r: &VerificationInput) -> VerificationResult {
    GraphiteCore::new().verify(r).expect("a verdict")
}

fn l5(r: &VerificationResult) -> (LayerStatus, String) {
    r.layers
        .iter()
        .find(|l| l.layer == "L5_SemanticVerification")
        .map(|l| (l.status, l.reason.clone()))
        .expect("L5 present")
}

/// The Risk Engine's findings, joined.
fn risk(r: &VerificationResult) -> String {
    r.risk_verdict
        .findings
        .iter()
        .map(|f| format!("{}: {}", f.pattern, f.reason))
        .collect::<Vec<_>>()
        .join(" || ")
}

/// Declared, grounded, and judged clean by the Risk Engine and L5.
fn assert_granted(r: &VerificationResult, what: &str) {
    let (status, reason) = l5(r);
    assert_eq!(status, LayerStatus::Passed, "{what}: L5 {reason}");
    assert_eq!(r.risk_verdict.status, "Clear", "{what}: {}", risk(r));
}

/// Refused, with `needle` in the Risk Engine's reason.
fn assert_refused(r: &VerificationResult, what: &str, needle: &str) {
    assert!(!r.approved, "{what}: approved");
    assert_eq!(r.risk_verdict.status, "Blocked", "{what}: {}", risk(r));
    assert!(
        risk(r).contains(needle),
        "{what}: expected '{needle}' in {}",
        risk(r)
    );
}

const MINT_X: &str = "So11111111111111111111111111111111111111112";
const MINT_Y: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

fn dlmm_accounts(name: &str, to_x: String, to_y: String) -> (InstructionDef, Vec<String>) {
    let d = def(DLMM, name);
    let a = accounts_for(
        DLMM,
        &d,
        &[
            ("sender", OWNER.to_string()),
            ("token_x_mint", MINT_X.to_string()),
            ("token_y_mint", MINT_Y.to_string()),
            ("user_token_x", to_x),
            ("user_token_y", to_y),
        ],
    );
    (d, a)
}

#[test]
fn a_liquidity_withdrawal_to_the_owners_own_accounts_is_declared_by_withdraw() {
    for name in [
        "remove_liquidity",
        "remove_liquidity_by_range",
        "remove_all_liquidity",
    ] {
        let (d, a) = dlmm_accounts(name, ata(OWNER, MINT_X), ata(OWNER, MINT_Y));
        assert_granted(&verify(&request(DLMM, &d, a, "withdraw")), name);
    }
    // A synonym of the intent is the intent.
    let (d, a) = dlmm_accounts("remove_liquidity", ata(OWNER, MINT_X), ata(OWNER, MINT_Y));
    assert_granted(
        &verify(&request(DLMM, &d, a, "remove_liquidity")),
        "synonym",
    );
}

#[test]
fn a_liquidity_withdrawal_paying_anyone_else_is_refused_and_says_why() {
    // One of the two legs to a stranger's associated account.
    let (d, a) = dlmm_accounts(
        "remove_liquidity",
        ata(OWNER, MINT_X),
        ata(STRANGER, MINT_Y),
    );
    let r = verify(&request(DLMM, &d, a, "withdraw"));
    assert_refused(
        &r,
        "stranger's ATA",
        "is not the associated token account of `sender`",
    );
    // To an account that is nobody's associated account (could be anyone's).
    let (d, a) = dlmm_accounts("remove_liquidity", filler(90), ata(OWNER, MINT_Y));
    assert_refused(
        &verify(&request(DLMM, &d, a, "withdraw")),
        "non-ATA",
        "is not the associated token account",
    );
    // The owner's ATA for the OTHER mint is not the owner's account for this one.
    let (d, a) = dlmm_accounts("remove_liquidity", ata(OWNER, MINT_Y), ata(OWNER, MINT_Y));
    assert_refused(
        &verify(&request(DLMM, &d, a, "withdraw")),
        "wrong mint",
        "is not the associated token account",
    );
}

#[test]
fn a_raydium_clmm_decrease_is_held_to_the_nft_owners_accounts() {
    let d = def(CLMM, "decrease_liquidity_v2");
    let base = |r0: String, r1: String| {
        accounts_for(
            CLMM,
            &d,
            &[
                ("nft_owner", OWNER.to_string()),
                ("vault_0_mint", MINT_X.to_string()),
                ("vault_1_mint", MINT_Y.to_string()),
                ("recipient_token_account_0", r0),
                ("recipient_token_account_1", r1),
            ],
        )
    };
    assert_granted(
        &verify(&request(
            CLMM,
            &d,
            base(ata(OWNER, MINT_X), ata(OWNER, MINT_Y)),
            "withdraw",
        )),
        "decrease_liquidity_v2",
    );
    assert_refused(
        &verify(&request(
            CLMM,
            &d,
            base(ata(OWNER, MINT_X), ata(STRANGER, MINT_Y)),
            "withdraw",
        )),
        "decrease to a stranger",
        "recipient_token_account_1",
    );
    // v1 names no mints, so its recipients cannot be tied to the owner: no
    // grant, refused as before.
    let v1 = def(CLMM, "decrease_liquidity");
    let a = accounts_for(CLMM, &v1, &[("nft_owner", OWNER.to_string())]);
    assert!(!verify(&request(CLMM, &v1, a, "withdraw")).approved);
}

#[test]
fn a_fee_claim_is_a_claim_and_never_a_withdrawal_of_principal() {
    let (d, a) = dlmm_accounts("claim_fee", ata(OWNER, MINT_X), ata(OWNER, MINT_Y));
    assert_granted(&verify(&request(DLMM, &d, a.clone(), "claim")), "claim_fee");
    assert_granted(
        &verify(&request(DLMM, &d, a.clone(), "collect_fees")),
        "synonym",
    );
    // The withdraw intent does not declare a claim, nor the claim intent a
    // withdrawal: each grant names one intent.
    let r = verify(&request(DLMM, &d, a, "withdraw"));
    assert!(!r.approved);
    assert_eq!(r.risk_verdict.status, "Blocked", "{}", risk(&r));
    let (d, a) = dlmm_accounts("remove_liquidity", ata(OWNER, MINT_X), ata(OWNER, MINT_Y));
    let r = verify(&request(DLMM, &d, a, "claim"));
    assert!(!r.approved);
    assert_eq!(r.risk_verdict.status, "Blocked", "{}", risk(&r));
}

#[test]
fn a_position_close_refunds_the_owner_or_is_refused() {
    for name in [
        "close_position",
        "close_position2",
        "close_position_if_empty",
    ] {
        let d = def(DLMM, name);
        let to = |receiver: &str| {
            accounts_for(
                DLMM,
                &d,
                &[
                    ("sender", OWNER.to_string()),
                    ("rent_receiver", receiver.to_string()),
                ],
            )
        };
        assert_granted(&verify(&request(DLMM, &d, to(OWNER), "close")), name);
        assert_refused(
            &verify(&request(DLMM, &d, to(STRANGER), "close")),
            name,
            "`rent_receiver`",
        );
    }
    // Pump's per-user accumulator: the user's own PDA, rent to the user.
    let d = def(PUMP_AMM, "close_user_volume_accumulator");
    let a = accounts_for(PUMP_AMM, &d, &[("user", OWNER.to_string())]);
    assert_granted(
        &verify(&request(PUMP_AMM, &d, a, "close")),
        "Pump accumulator",
    );
    // Raydium CLMM close_position: the rent goes to the signing nft_owner.
    let d = def(CLMM, "close_position");
    let a = accounts_for(CLMM, &d, &[("nft_owner", OWNER.to_string())]);
    assert_granted(
        &verify(&request(CLMM, &d, a, "close")),
        "CLMM close_position",
    );
}

#[test]
fn a_burn_is_of_the_signers_own_tokens() {
    let d = def(TOKEN, "Burn");
    let with = |account: String| {
        accounts_for(
            TOKEN,
            &d,
            &[
                ("account", account),
                ("mint", MINT_Y.to_string()),
                ("authority", OWNER.to_string()),
            ],
        )
    };
    assert_granted(
        &verify(&request(TOKEN, &d, with(ata(OWNER, MINT_Y)), "burn")),
        "own burn",
    );
    // A burn from an account that is not the authority's own associated
    // account — a delegate's burn of someone else's tokens looks like this.
    assert_refused(
        &verify(&request(TOKEN, &d, with(ata(STRANGER, MINT_Y)), "burn")),
        "delegate burn",
        "`account`",
    );
    // `burn` never declares a mint, under any accounts.
    let mint_to = def(TOKEN, "MintTo");
    let a = accounts_for(TOKEN, &mint_to, &[("authority", OWNER.to_string())]);
    let r = verify(&request(TOKEN, &mint_to, a, "burn"));
    assert!(!r.approved);
    assert_eq!(r.risk_verdict.status, "Blocked", "{}", risk(&r));
}

#[test]
fn an_owner_updating_its_own_offer_is_configuration_and_nothing_else_is() {
    let usdc = MINT_Y.to_string();
    let d = def(MARKETPLACE, "update_offer");
    // The escrow PDA is derived first (its seeds name the buyer), then its
    // associated USDC account.
    let pre = accounts_for(
        MARKETPLACE,
        &d,
        &[("buyer", OWNER.to_string()), ("usdc_mint", usdc.clone())],
    );
    let escrow_slot = d
        .accounts
        .iter()
        .position(|a| a.name == "buyer_user_escrow_account")
        .unwrap();
    let escrow = pre[escrow_slot].clone();
    let build = |buyer_usdc: String| {
        accounts_for(
            MARKETPLACE,
            &d,
            &[
                ("buyer", OWNER.to_string()),
                ("usdc_mint", usdc.clone()),
                ("buyer_usdc_account", buyer_usdc),
                ("buyer_user_escrow_token_account", ata(&escrow, MINT_Y)),
            ],
        )
    };
    assert_granted(
        &verify(&request(
            MARKETPLACE,
            &d,
            build(ata(OWNER, MINT_Y)),
            "configure",
        )),
        "update_offer",
    );
    // Its USDC leg to a stranger: not the owner's own operation.
    assert_refused(
        &verify(&request(
            MARKETPLACE,
            &d,
            build(ata(STRANGER, MINT_Y)),
            "configure",
        )),
        "update_offer to stranger",
        "`buyer_usdc_account`",
    );
    // Without the configure intent it is what it was: an authority-tagged
    // instruction no intent declares.
    let r = verify(&request(
        MARKETPLACE,
        &d,
        build(ata(OWNER, MINT_Y)),
        "transfer",
    ));
    assert!(!r.approved);
    assert_eq!(r.risk_verdict.status, "Blocked");
    // MMM `updatePool` has no grant (its IDL is not in the repository, so
    // what its arguments can change is unverified): still refused under
    // `configure`, as an authority change.
    let up = def(MMM, "updatePool");
    let a = accounts_for(MMM, &up, &[("owner", OWNER.to_string())]);
    let r = verify(&request(MMM, &up, a, "configure"));
    assert!(!r.approved);
    assert_eq!(r.risk_verdict.status, "Blocked", "{}", risk(&r));
}

#[test]
fn the_new_intents_declare_nothing_but_their_grants() {
    // A System transfer to a stranger under each new intent.
    let transfer = def(SYSTEM, "Transfer");
    for intent in [
        "withdraw",
        "claim",
        "burn",
        "configure",
        "redeem",
        "harvest",
    ] {
        let a = vec![OWNER.to_string(), STRANGER.to_string()];
        let r = verify(&request(SYSTEM, &transfer, a, intent));
        assert!(!r.approved, "{intent} on a System transfer");
        assert_eq!(r.risk_verdict.status, "Blocked", "{intent}: {}", risk(&r));
    }
    // An ungranted withdraw-class instruction (Kamino Vault `withdraw`).
    let kv = def(KAMINO_VAULT, "withdraw");
    let a = accounts_for(KAMINO_VAULT, &kv, &[]);
    let r = verify(&request(KAMINO_VAULT, &kv, a, "withdraw"));
    assert!(!r.approved);
    assert_eq!(r.risk_verdict.status, "Blocked", "{}", risk(&r));
    // A granted instruction is not declared by `transfer`, and with NO
    // intent it is a high-risk class nobody stated (Check 10).
    let (d, a) = dlmm_accounts("remove_liquidity", ata(OWNER, MINT_X), ata(OWNER, MINT_Y));
    for intent in ["transfer", "swap", "stake", ""] {
        let r = verify(&request(DLMM, &d, a.clone(), intent));
        assert!(!r.approved, "'{intent}'");
        assert_eq!(r.risk_verdict.status, "Blocked", "'{intent}': {}", risk(&r));
    }
}

#[test]
fn the_close_intent_does_not_reach_an_ungranted_close_on_a_granted_program() {
    // DLMM has close grants; an instruction of the same program it does
    // not grant stays outside the close intent.
    let registry = load_seed_manifests();
    let granted: Vec<&str> = graphite_core::intent_grants::GRANTS
        .iter()
        .filter(|g| g.program_id == DLMM)
        .map(|g| g.instruction)
        .collect();
    let m = registry.get(DLMM).unwrap();
    let mut checked = 0;
    for i in m
        .instructions
        .iter()
        .filter(|i| !granted.contains(&i.name.as_str()))
    {
        if !matches!(i.security_class(), "close" | "withdraw") {
            continue;
        }
        let a = accounts_for(DLMM, i, &[]);
        for intent in ["close", "withdraw", "claim"] {
            let r = verify(&request(DLMM, i, a.clone(), intent));
            assert!(!r.approved, "{} under {intent}", i.name);
            assert_eq!(
                r.risk_verdict.status,
                "Blocked",
                "{} under {intent}: {}",
                i.name,
                risk(&r)
            );
        }
        checked += 1;
    }
    assert!(
        checked > 0,
        "DLMM has ungranted close/withdraw instructions to check"
    );
}

// ── Round 32 (R30-G-1): a granted withdrawal's minimum outputs ─────────────

const CPMM: &str = "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C";

/// The three granted withdrawals with minimum outputs, each with its
/// accounts paying the owner's own associated token accounts, and the IDL's
/// argument layout after the discriminator: the u64s before the minimums
/// (as little-endian words of 8 bytes), then the minimums' names.
struct MinOutCase {
    program: &'static str,
    name: &'static str,
    /// Bytes of arguments before the first minimum.
    lead: usize,
    minimums: [&'static str; 2],
    accounts: fn(&InstructionDef) -> Vec<String>,
}

fn min_out_cases() -> [MinOutCase; 3] {
    [
        MinOutCase {
            program: CLMM,
            name: "decrease_liquidity_v2",
            // liquidity: u128
            lead: 16,
            minimums: ["amount_0_min", "amount_1_min"],
            accounts: |d| {
                accounts_for(
                    CLMM,
                    d,
                    &[
                        ("nft_owner", OWNER.to_string()),
                        ("vault_0_mint", MINT_X.to_string()),
                        ("vault_1_mint", MINT_Y.to_string()),
                        ("recipient_token_account_0", ata(OWNER, MINT_X)),
                        ("recipient_token_account_1", ata(OWNER, MINT_Y)),
                    ],
                )
            },
        },
        MinOutCase {
            program: CPMM,
            name: "withdraw",
            // lp_token_amount: u64
            lead: 8,
            minimums: ["minimum_token_0_amount", "minimum_token_1_amount"],
            accounts: |d| {
                accounts_for(
                    CPMM,
                    d,
                    &[
                        ("owner", OWNER.to_string()),
                        ("vault_0_mint", MINT_X.to_string()),
                        ("vault_1_mint", MINT_Y.to_string()),
                        ("token_0_account", ata(OWNER, MINT_X)),
                        ("token_1_account", ata(OWNER, MINT_Y)),
                    ],
                )
            },
        },
        MinOutCase {
            program: PUMP_AMM,
            name: "withdraw",
            // lp_token_amount_in: u64
            lead: 8,
            minimums: ["min_base_amount_out", "min_quote_amount_out"],
            accounts: |d| {
                accounts_for(
                    PUMP_AMM,
                    d,
                    &[
                        ("user", OWNER.to_string()),
                        ("base_mint", MINT_X.to_string()),
                        ("quote_mint", MINT_Y.to_string()),
                        ("user_base_token_account", ata(OWNER, MINT_X)),
                        ("user_quote_token_account", ata(OWNER, MINT_Y)),
                    ],
                )
            },
        },
    ]
}

/// The arguments: `lead` bytes of a non-zero amount, then the two minimums.
fn min_out_args(lead: usize, first: u64, second: u64) -> Vec<u8> {
    let mut args = vec![7u8; lead];
    args.extend_from_slice(&first.to_le_bytes());
    args.extend_from_slice(&second.to_le_bytes());
    args
}

/// A granted withdrawal that sets every minimum output to zero accepts any
/// amount out: refused, as an unbounded withdrawal, naming its arguments —
/// per program, with the accounts that make it the owner's own.
#[test]
fn a_granted_withdrawal_with_every_minimum_output_zero_is_refused() {
    for c in min_out_cases() {
        let d = def(c.program, c.name);
        let r = verify(&request_with_args(
            c.program,
            &d,
            (c.accounts)(&d),
            "withdraw",
            &min_out_args(c.lead, 0, 0),
        ));
        let what = format!("{} {}", c.program, c.name);
        assert_refused(&r, &what, "UnboundedWithdrawal");
        let findings = &r.risk_verdict.findings;
        assert!(
            findings.iter().any(|f| f.pattern == "UnboundedWithdrawal"),
            "{what}: {}",
            risk(&r)
        );
        for m in c.minimums {
            assert!(risk(&r).contains(m), "{what}: {m} in {}", risk(&r));
        }
        assert!(
            risk(&r).contains("GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS"),
            "{what}: names the opt-out"
        );
    }
}

/// Controls: a non-zero minimum on every output bounds the withdrawal, and it
/// is granted as before.
///
/// Round 34 (R33-11) re-pin: this test also granted `(0, 1)` and `(1, 0)` —
/// "a non-zero minimum on EITHER output bounds the withdrawal". It does not:
/// the zero side accepts any amount, and whoever moves the pool first takes
/// it. See `a_withdrawal_with_a_dust_minimum_is_not_bounded`.
#[test]
fn a_granted_withdrawal_with_a_non_zero_minimum_output_is_granted() {
    for c in min_out_cases() {
        let d = def(c.program, c.name);
        for (first, second) in [(1_000, 2_000), (1, 1)] {
            let r = verify(&request_with_args(
                c.program,
                &d,
                (c.accounts)(&d),
                "withdraw",
                &min_out_args(c.lead, first, second),
            ));
            assert_granted(&r, &format!("{} {} ({first}, {second})", c.program, c.name));
        }
    }
}

/// Round 34 (R33-11): `UnboundedWithdrawal` fired only when EVERY minimum was
/// zero, so `amount_0_min = 1, amount_1_min = 0` — one side bounded by a
/// token's smallest unit, the other not at all — kept its grant. A zero
/// minimum leaves its output to whoever moves the pool in front of the
/// withdrawal, whatever the other minimum says: refused, naming the zero one.
/// (Whether a non-zero minimum like `1` is fair is not judged — that needs the
/// expected output, which the instruction's bytes do not carry.)
#[test]
fn a_withdrawal_with_a_dust_minimum_is_not_bounded() {
    for c in min_out_cases() {
        let d = def(c.program, c.name);
        for (first, second, zero) in [(1, 0, c.minimums[1]), (0, 1, c.minimums[0])] {
            let r = verify(&request_with_args(
                c.program,
                &d,
                (c.accounts)(&d),
                "withdraw",
                &min_out_args(c.lead, first, second),
            ));
            let what = format!("{} {} ({first}, {second})", c.program, c.name);
            assert_refused(&r, &what, "UnboundedWithdrawal");
            assert!(
                r.risk_verdict
                    .findings
                    .iter()
                    .any(|f| f.pattern == "UnboundedWithdrawal"),
                "{what}: {}",
                risk(&r)
            );
            assert!(
                risk(&r).contains(zero),
                "{what}: names {zero}: {}",
                risk(&r)
            );
        }
    }
}

/// Data too short to hold the minimums cannot show they bound anything: the
/// grant does not hold.
#[test]
fn a_granted_withdrawal_whose_minimums_cannot_be_read_is_refused() {
    for c in min_out_cases() {
        let d = def(c.program, c.name);
        let mut args = min_out_args(c.lead, 1_000, 2_000);
        args.truncate(c.lead + 12);
        let r = verify(&request_with_args(
            c.program,
            &d,
            (c.accounts)(&d),
            "withdraw",
            &args,
        ));
        assert_refused(&r, c.name, "too few to hold");
    }
}

/// The operator's opt-out (`GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS`) lets the
/// zero-minimum withdrawal keep its grant; the accounts are still judged.
#[test]
fn the_operator_may_allow_unbounded_withdrawals() {
    let mut core = GraphiteCore::new();
    core.set_allow_unbounded_withdrawals(true);
    for c in min_out_cases() {
        let d = def(c.program, c.name);
        let r = core
            .verify(&request_with_args(
                c.program,
                &d,
                (c.accounts)(&d),
                "withdraw",
                &min_out_args(c.lead, 0, 0),
            ))
            .expect("a verdict");
        assert_granted(&r, c.name);
    }
    // The opt-out is about amounts only: a stranger's account still fails.
    let d = def(CPMM, "withdraw");
    let a = accounts_for(
        CPMM,
        &d,
        &[
            ("owner", OWNER.to_string()),
            ("vault_0_mint", MINT_X.to_string()),
            ("vault_1_mint", MINT_Y.to_string()),
            ("token_0_account", ata(OWNER, MINT_X)),
            ("token_1_account", ata(STRANGER, MINT_Y)),
        ],
    );
    let r = core
        .verify(&request_with_args(
            CPMM,
            &d,
            a,
            "withdraw",
            &min_out_args(8, 0, 0),
        ))
        .expect("a verdict");
    assert_refused(&r, "stranger, opted out", "token_1_account");
}

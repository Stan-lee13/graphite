//! Grounded intent grants (roadmap R-M13 / R-M14, Round 30).
//!
//! Since external review R2 an intent declares only the security classes
//! `manifest::INTENT_DECLARES` lists, and no intent declared a lending or
//! liquidity withdrawal, a fee claim, a protocol position close, a burn, or
//! an owner configuring its own object. Those instructions were refused
//! whatever label an honest agent gave them (measured: 219 of 48,855 executed
//! mainnet transactions newly refused by R2, and 9 owner configurations
//! refused as protocol administration).
//!
//! Widening the table by CLASS would undo R2: a `withdraw` intent that
//! declares the `withdraw` class declares all 414 of them, among them
//! withdrawals whose destination is any account the caller names. So the
//! vocabulary is widened per INSTRUCTION instead, by the grants below. A grant
//! names one instruction of one program, the one intent that describes it, the
//! account that must sign as its owner, and the facts about the transaction's
//! own accounts that make the operation the owner's own:
//!
//! - [`Grounding::AssociatedTokenAccount`]: the account the funds go to is the
//!   owner's associated token account for the mint the instruction names —
//!   checked by deriving it, so the owner is proven, not assumed.
//! - [`Grounding::SameKey`]: the account rent is refunded to is the owner.
//! - [`Grounding::SeededBy`]: the object is a PDA whose manifest seeds include
//!   the owner's key; L4 refuses an address that does not derive.
//!
//! Each fact is read from the accounts the instruction carries (from the bytes
//! when the request is artifact-bound), never from the request's prose or
//! parameters. A grant whose facts hold gives the instruction a GROUNDED class
//! (`withdraw_to_owner`, `claim_to_owner`, `close_to_owner`, `burn_own`,
//! `owner_configure`) that only its intent declares; one whose facts do not
//! hold leaves the manifest's class in place, so the instruction is refused as
//! before, and says which fact failed.
//!
//! The grounded classes are not in `manifest::RISK_CLASSES`: a manifest —
//! seed or community — cannot declare one. Only this table can, and it is
//! code, reviewed like code. A grant is added only when the program's IDL (or
//! source) says what the instruction does with each named account; the
//! `source` of each entry says where that came from.
//!
//! What a grant does NOT judge: amounts (how much is withdrawn, any minimum
//! out), which is the signer's own business and the agent guard's grounding
//! (a withdrawal at a manipulated price is an economics question, like a swap's
//! minimum out). Operations no grant covers keep their R2 refusal; a mint
//! stays refused under every intent (minting needs a mint authority, and an
//! agent wallet holding one is administering a token, not using it).

use crate::manifest::InstructionDef;
use crate::solana_types::{find_program_address, Pubkey};

/// The associated-token-account program.
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
/// The two token programs an associated token account can belong to. The
/// derivation includes the token program, so matching either one proves the
/// owner: a different owner derives a different address under both.
const TOKEN_PROGRAMS: [&str; 2] = [
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
];

/// A fact about an instruction's accounts that makes the operation the
/// owner's own. Account roles are the manifest's names for the slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grounding {
    /// `account` is the associated token account of `owner` for `mint`.
    AssociatedTokenAccount {
        account: &'static str,
        owner: &'static str,
        mint: &'static str,
    },
    /// `account` (where rent or lamports go) is the same key as `owner`.
    SameKey {
        account: &'static str,
        owner: &'static str,
    },
    /// `account` is a PDA whose manifest seed templates name `owner`'s slot.
    /// The derivation itself is L4's (a mismatch is an identity block); this
    /// checks that the seeds that derivation uses include the owner.
    SeededBy {
        account: &'static str,
        owner: &'static str,
    },
}

/// One instruction an intent may declare, and the facts that must hold.
#[derive(Debug, Clone, Copy)]
pub struct IntentGrant {
    pub program_id: &'static str,
    /// The manifest's instruction name.
    pub instruction: &'static str,
    /// The canonical intent (`risk_engine::canonical_intent`) that declares it.
    pub intent: &'static str,
    /// The grounded class it is judged by when every fact holds.
    pub class: &'static str,
    /// The role that must be a required signer in every layout: whose
    /// operation this is.
    pub owner: &'static str,
    pub grounding: &'static [Grounding],
    /// Where the account semantics come from.
    pub source: &'static str,
}

/// The grounded classes. None is a manifest class (`manifest::RISK_CLASSES`),
/// so only [`GRANTS`] can give one.
pub const WITHDRAW_TO_OWNER: &str = "withdraw_to_owner";
pub const CLAIM_TO_OWNER: &str = "claim_to_owner";
pub const CLOSE_TO_OWNER: &str = "close_to_owner";
pub const BURN_OWN: &str = "burn_own";
pub const OWNER_CONFIGURE: &str = "owner_configure";
pub const GROUNDED_CLASSES: &[&str] = &[
    WITHDRAW_TO_OWNER,
    CLAIM_TO_OWNER,
    CLOSE_TO_OWNER,
    BURN_OWN,
    OWNER_CONFIGURE,
];

/// Whether `class` is one only a grant can give.
pub fn is_grounded_class(class: &str) -> bool {
    GROUNDED_CLASSES.contains(&class)
}

const RAYDIUM_CLMM: &str = "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK";
const RAYDIUM_CPMM: &str = "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C";
const METEORA_DLMM: &str = "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo";
const PUMP_AMM: &str = "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA";
const PUMP_FUN: &str = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";
const MARKETPLACE_CCMR: &str = "CcmRKTuZCGJBWQwMHvDYApBRvSZNHqGJXkznqpDTSQUr";

const DLMM_TO_SENDER: &[Grounding] = &[
    Grounding::AssociatedTokenAccount {
        account: "user_token_x",
        owner: "sender",
        mint: "token_x_mint",
    },
    Grounding::AssociatedTokenAccount {
        account: "user_token_y",
        owner: "sender",
        mint: "token_y_mint",
    },
];
const DLMM_IDL: &str = "graphite-core/scripts/idls/meteora-dlmm.json: user_token_x/user_token_y receive the position's tokens; sender is the position's owner or operator";
const DLMM_RENT_TO_SENDER: &[Grounding] = &[Grounding::SameKey {
    account: "rent_receiver",
    owner: "sender",
}];
const VOLUME_ACCUMULATOR: &[Grounding] = &[Grounding::SeededBy {
    account: "user_volume_accumulator",
    owner: "user",
}];
const BURN_FROM_OWN_ATA: &[Grounding] = &[Grounding::AssociatedTokenAccount {
    account: "account",
    owner: "authority",
    mint: "mint",
}];

/// Every grant. Kept small on purpose: each entry is an instruction whose
/// account semantics were read from its IDL, and each is pinned by the tests
/// below against the seed manifests (the instruction exists, every role is in
/// every layout, the owner is a required signer, the seeds name the owner).
pub const GRANTS: &[IntentGrant] = &[
    // Raydium CLMM: decreasing a position pays its tokens to the two
    // recipient accounts, which the program does not constrain to the owner.
    // `decrease_liquidity` (v1) names no mints, so its recipients cannot be
    // tied to the owner from the accounts: no grant, still refused.
    IntentGrant {
        program_id: RAYDIUM_CLMM,
        instruction: "decrease_liquidity_v2",
        intent: "withdraw",
        class: WITHDRAW_TO_OWNER,
        owner: "nft_owner",
        grounding: &[
            Grounding::AssociatedTokenAccount {
                account: "recipient_token_account_0",
                owner: "nft_owner",
                mint: "vault_0_mint",
            },
            Grounding::AssociatedTokenAccount {
                account: "recipient_token_account_1",
                owner: "nft_owner",
                mint: "vault_1_mint",
            },
        ],
        source: "graphite-core/scripts/idls/raydium_clmm.json decrease_liquidity_v2: recipient_token_account_0/1 \"the destination token account for receive amount_0/1\", unconstrained",
    },
    // Closing a position burns its NFT and refunds the rent to the signer,
    // which the IDL marks the writable nft_owner; no other account is paid.
    IntentGrant {
        program_id: RAYDIUM_CLMM,
        instruction: "close_position",
        intent: "close",
        class: CLOSE_TO_OWNER,
        owner: "nft_owner",
        grounding: &[],
        source: "graphite-core/scripts/idls/raydium_clmm.json close_position: nft_owner signer+writable receives the closed accounts' rent; personal_position seeds [position, position_nft_mint]",
    },
    IntentGrant {
        program_id: RAYDIUM_CPMM,
        instruction: "withdraw",
        intent: "withdraw",
        class: WITHDRAW_TO_OWNER,
        owner: "owner",
        grounding: &[
            Grounding::AssociatedTokenAccount {
                account: "token_0_account",
                owner: "owner",
                mint: "vault_0_mint",
            },
            Grounding::AssociatedTokenAccount {
                account: "token_1_account",
                owner: "owner",
                mint: "vault_1_mint",
            },
        ],
        source: "graphite-core/scripts/idls/raydium_cpmm.json withdraw: token_0_account/token_1_account \"the token account for receive token_0/1\", unconstrained; the LP burned from owner_lp_token under owner's signature",
    },
    IntentGrant {
        program_id: METEORA_DLMM,
        instruction: "remove_liquidity",
        intent: "withdraw",
        class: WITHDRAW_TO_OWNER,
        owner: "sender",
        grounding: DLMM_TO_SENDER,
        source: DLMM_IDL,
    },
    IntentGrant {
        program_id: METEORA_DLMM,
        instruction: "remove_liquidity2",
        intent: "withdraw",
        class: WITHDRAW_TO_OWNER,
        owner: "sender",
        grounding: DLMM_TO_SENDER,
        source: DLMM_IDL,
    },
    IntentGrant {
        program_id: METEORA_DLMM,
        instruction: "remove_liquidity_by_range",
        intent: "withdraw",
        class: WITHDRAW_TO_OWNER,
        owner: "sender",
        grounding: DLMM_TO_SENDER,
        source: DLMM_IDL,
    },
    IntentGrant {
        program_id: METEORA_DLMM,
        instruction: "remove_liquidity_by_range2",
        intent: "withdraw",
        class: WITHDRAW_TO_OWNER,
        owner: "sender",
        grounding: DLMM_TO_SENDER,
        source: DLMM_IDL,
    },
    IntentGrant {
        program_id: METEORA_DLMM,
        instruction: "remove_all_liquidity",
        intent: "withdraw",
        class: WITHDRAW_TO_OWNER,
        owner: "sender",
        grounding: DLMM_TO_SENDER,
        source: DLMM_IDL,
    },
    // A fee claim pays the position's accrued fees, not its principal: the
    // claim intent declares it and the withdraw intent does not.
    IntentGrant {
        program_id: METEORA_DLMM,
        instruction: "claim_fee",
        intent: "claim",
        class: CLAIM_TO_OWNER,
        owner: "sender",
        grounding: DLMM_TO_SENDER,
        source: DLMM_IDL,
    },
    IntentGrant {
        program_id: METEORA_DLMM,
        instruction: "claim_fee2",
        intent: "claim",
        class: CLAIM_TO_OWNER,
        owner: "sender",
        grounding: DLMM_TO_SENDER,
        source: DLMM_IDL,
    },
    IntentGrant {
        program_id: METEORA_DLMM,
        instruction: "close_position",
        intent: "close",
        class: CLOSE_TO_OWNER,
        owner: "sender",
        grounding: DLMM_RENT_TO_SENDER,
        source: "graphite-core/scripts/idls/meteora-dlmm.json close_position: the position's rent goes to rent_receiver, which the program does not constrain",
    },
    IntentGrant {
        program_id: METEORA_DLMM,
        instruction: "close_position2",
        intent: "close",
        class: CLOSE_TO_OWNER,
        owner: "sender",
        grounding: DLMM_RENT_TO_SENDER,
        source: "graphite-core/scripts/idls/meteora-dlmm.json close_position2: rent to rent_receiver, unconstrained",
    },
    IntentGrant {
        program_id: METEORA_DLMM,
        instruction: "close_position_if_empty",
        intent: "close",
        class: CLOSE_TO_OWNER,
        owner: "sender",
        grounding: DLMM_RENT_TO_SENDER,
        source: "graphite-core/scripts/idls/meteora-dlmm.json close_position_if_empty: rent to rent_receiver, unconstrained",
    },
    IntentGrant {
        program_id: PUMP_AMM,
        instruction: "withdraw",
        intent: "withdraw",
        class: WITHDRAW_TO_OWNER,
        owner: "user",
        grounding: &[
            Grounding::AssociatedTokenAccount {
                account: "user_base_token_account",
                owner: "user",
                mint: "base_mint",
            },
            Grounding::AssociatedTokenAccount {
                account: "user_quote_token_account",
                owner: "user",
                mint: "quote_mint",
            },
        ],
        source: "protocols/pump-amm manifest (Pump AMM IDL): user_base_token_account/user_quote_token_account receive the withdrawn liquidity, LP burned from user_pool_token_account under user's signature",
    },
    // Pump's volume accumulator is the user's own PDA; closing it refunds
    // its rent to the user, who signs and is writable.
    IntentGrant {
        program_id: PUMP_AMM,
        instruction: "close_user_volume_accumulator",
        intent: "close",
        class: CLOSE_TO_OWNER,
        owner: "user",
        grounding: VOLUME_ACCUMULATOR,
        source: "Pump AMM IDL: user_volume_accumulator seeds [\"user_volume_accumulator\", user]; rent returned to user (signer, writable)",
    },
    IntentGrant {
        program_id: PUMP_FUN,
        instruction: "close_user_volume_accumulator",
        intent: "close",
        class: CLOSE_TO_OWNER,
        owner: "user",
        grounding: VOLUME_ACCUMULATOR,
        source: "Pump.fun IDL: user_volume_accumulator seeds [\"user_volume_accumulator\", user]; rent returned to user (signer, writable)",
    },
    // A burn destroys the signer's own tokens; held to the signer's own
    // associated token account, so a delegate's burn of someone else's
    // tokens is not one.
    IntentGrant {
        program_id: TOKEN_PROGRAMS[0],
        instruction: "Burn",
        intent: "burn",
        class: BURN_OWN,
        owner: "authority",
        grounding: BURN_FROM_OWN_ATA,
        source: "SPL Token Burn: [account (w), mint (w), authority (s)]",
    },
    IntentGrant {
        program_id: TOKEN_PROGRAMS[0],
        instruction: "BurnChecked",
        intent: "burn",
        class: BURN_OWN,
        owner: "authority",
        grounding: BURN_FROM_OWN_ATA,
        source: "SPL Token BurnChecked: [account (w), mint (w), authority (s)]",
    },
    IntentGrant {
        program_id: TOKEN_PROGRAMS[1],
        instruction: "Burn",
        intent: "burn",
        class: BURN_OWN,
        owner: "authority",
        grounding: BURN_FROM_OWN_ATA,
        source: "Token-2022 Burn: [account (w), mint (w), authority (s)]",
    },
    IntentGrant {
        program_id: TOKEN_PROGRAMS[1],
        instruction: "BurnChecked",
        intent: "burn",
        class: BURN_OWN,
        owner: "authority",
        grounding: BURN_FROM_OWN_ATA,
        source: "Token-2022 BurnChecked: [account (w), mint (w), authority (s)]",
    },
    // R-M13: an owner changing its own offer. The offer and the escrow are
    // PDAs seeded by the buyer (L4 derives them), and the USDC moves between
    // the buyer's own associated account and the buyer's escrow's.
    IntentGrant {
        program_id: MARKETPLACE_CCMR,
        instruction: "update_offer",
        intent: "configure",
        class: OWNER_CONFIGURE,
        owner: "buyer",
        grounding: &[
            Grounding::SeededBy {
                account: "offer",
                owner: "buyer",
            },
            Grounding::SeededBy {
                account: "buyer_user_escrow_account",
                owner: "buyer",
            },
            Grounding::AssociatedTokenAccount {
                account: "buyer_usdc_account",
                owner: "buyer",
                mint: "usdc_mint",
            },
            Grounding::AssociatedTokenAccount {
                account: "buyer_user_escrow_token_account",
                owner: "buyer_user_escrow_account",
                mint: "usdc_mint",
            },
        ],
        source: "protocols/marketplace-ccmrkt manifest (IDL): offer seeds [offer, asset_id, buyer], buyer_user_escrow_account seeds [user_escrow, buyer]",
    },
];

/// What the grants make of one instruction under one intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantOutcome {
    /// No grant names this instruction for this intent: the manifest's class
    /// stands.
    NoGrant,
    /// A grant's every fact holds: the instruction is judged by this class.
    Grounded(&'static str),
    /// A grant names it, and a fact does not hold: the manifest's class
    /// stands, and this says why the grant did not apply.
    Ungrounded(String),
}

/// The grant for this instruction under this canonical intent, if any.
pub fn grant_for(
    program_id: &str,
    instruction: &str,
    canonical_intent: &str,
) -> Option<&'static IntentGrant> {
    GRANTS.iter().find(|g| {
        g.program_id == program_id && g.instruction == instruction && g.intent == canonical_intent
    })
}

/// Whether any grant gives `program_id` an instruction this intent declares.
pub fn program_has_grant(program_id: &str, canonical_intent: &str) -> bool {
    GRANTS
        .iter()
        .any(|g| g.program_id == program_id && g.intent == canonical_intent)
}

/// The class `def` (an instruction of `program_id`, carrying `accounts` in
/// the transaction's order) is judged by under `canonical_intent`.
pub fn ground(
    program_id: &str,
    def: &InstructionDef,
    canonical_intent: &str,
    accounts: &[String],
) -> GrantOutcome {
    let Some(grant) = grant_for(program_id, &def.name, canonical_intent) else {
        return GrantOutcome::NoGrant;
    };
    match check(grant, def, accounts) {
        Ok(()) => GrantOutcome::Grounded(grant.class),
        Err(why) => GrantOutcome::Ungrounded(format!(
            "a '{}' intent declares {} only when the operation is the owner's own, and {why}",
            grant.intent, grant.instruction
        )),
    }
}

fn check(grant: &IntentGrant, def: &InstructionDef, accounts: &[String]) -> Result<(), String> {
    let layout = def.layout_for(accounts.len());
    if layout.len() != accounts.len() {
        return Err(format!(
            "the instruction carries {} account(s) where its layout names {}",
            accounts.len(),
            layout.len()
        ));
    }
    let slot = |role: &str| -> Result<usize, String> {
        layout
            .iter()
            .position(|a| a.name == role)
            .ok_or_else(|| format!("its layout has no `{role}` account"))
    };
    let key = |role: &str| -> Result<&str, String> { Ok(accounts[slot(role)?].as_str()) };
    let owner_slot = slot(grant.owner)?;
    if !layout[owner_slot].is_signer || layout[owner_slot].optional {
        return Err(format!("`{}` is not a required signer", grant.owner));
    }
    for fact in grant.grounding {
        match *fact {
            Grounding::AssociatedTokenAccount {
                account,
                owner,
                mint,
            } => {
                let (account_key, owner_key, mint_key) = (key(account)?, key(owner)?, key(mint)?);
                if !is_associated_token_account(account_key, owner_key, mint_key) {
                    return Err(format!(
                        "`{account}` ({account_key}) is not the associated token account of `{owner}` ({owner_key}) for `{mint}` ({mint_key}) — the funds would not be provably the owner's"
                    ));
                }
            }
            Grounding::SameKey { account, owner } => {
                let (a, o) = (key(account)?, key(owner)?);
                if a != o {
                    return Err(format!(
                        "`{account}` ({a}) is not `{owner}` ({o}) — the refund would go to another key"
                    ));
                }
            }
            Grounding::SeededBy { account, owner } => {
                let seeds = &layout[slot(account)?].pda_seeds;
                let owner_seed = format!("{{account_{}}}", slot(owner)?);
                if !seeds.iter().any(|s| *s == owner_seed) {
                    return Err(format!(
                        "`{account}`'s seeds {seeds:?} do not name `{owner}`"
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Whether `account` is the associated token account of `owner` for `mint`
/// under either token program.
pub fn is_associated_token_account(account: &str, owner: &str, mint: &str) -> bool {
    let (Ok(account), Ok(owner), Ok(mint), Ok(ata_program)) = (
        Pubkey::from_base58(account),
        Pubkey::from_base58(owner),
        Pubkey::from_base58(mint),
        Pubkey::from_base58(ATA_PROGRAM),
    ) else {
        return false;
    };
    TOKEN_PROGRAMS.iter().any(|tp| {
        let Ok(tp) = Pubkey::from_base58(tp) else {
            return false;
        };
        find_program_address(
            &[owner.as_bytes(), tp.as_bytes(), mint.as_bytes()],
            &ata_program,
        )
        .is_ok_and(|(derived, _)| derived == account)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_def(program: &str, name: &str) -> InstructionDef {
        let registry = crate::manifest::load_seed_manifests();
        registry
            .get(program)
            .unwrap_or_else(|| panic!("{program} has a seed manifest"))
            .instructions
            .iter()
            .find(|i| i.name == name)
            .unwrap_or_else(|| panic!("{program} declares {name}"))
            .clone()
    }

    #[test]
    fn every_grant_names_a_seed_instruction_its_roles_and_a_signing_owner() {
        for g in GRANTS {
            let def = seed_def(g.program_id, g.instruction);
            for layout in def.all_layouts() {
                let has = |role: &str| layout.iter().any(|a| a.name == role);
                let owner = layout
                    .iter()
                    .find(|a| a.name == g.owner)
                    .unwrap_or_else(|| panic!("{}: no owner role {}", g.instruction, g.owner));
                assert!(
                    owner.is_signer && !owner.optional,
                    "{}: owner must sign",
                    g.instruction
                );
                for fact in g.grounding {
                    let roles: Vec<&str> = match *fact {
                        Grounding::AssociatedTokenAccount {
                            account,
                            owner,
                            mint,
                        } => {
                            vec![account, owner, mint]
                        }
                        Grounding::SameKey { account, owner } => vec![account, owner],
                        Grounding::SeededBy { account, owner } => vec![account, owner],
                    };
                    for r in roles {
                        assert!(has(r), "{}: role {r} is not in a layout", g.instruction);
                    }
                    if let Grounding::SeededBy { account, owner } = *fact {
                        let i = layout.iter().position(|a| a.name == owner).unwrap();
                        let seeds = &layout.iter().find(|a| a.name == account).unwrap().pda_seeds;
                        assert!(
                            seeds.contains(&format!("{{account_{i}}}")),
                            "{}: {account} seeds {seeds:?} must name {owner}",
                            g.instruction
                        );
                    }
                }
            }
            assert!(is_grounded_class(g.class));
            assert_eq!(
                crate::risk_engine::canonical_intent(g.intent),
                g.intent,
                "a grant names a canonical intent"
            );
            assert_eq!(
                crate::manifest::intent_declares_class(g.intent, g.class),
                Some(true),
                "{}: its intent declares its class",
                g.instruction
            );
        }
    }

    #[test]
    fn a_close_grant_is_only_for_an_instruction_without_a_stranger_payee() {
        // A close grant with no SameKey fact relies on the IDL: the owner is
        // the instruction's only writable non-PDA, non-program account that
        // is not being closed. Pinned so a manifest change re-opens the
        // question.
        for g in GRANTS
            .iter()
            .filter(|g| g.class == CLOSE_TO_OWNER && g.grounding.is_empty())
        {
            let def = seed_def(g.program_id, g.instruction);
            let owner = def.accounts.iter().find(|a| a.name == g.owner).unwrap();
            assert!(
                owner.is_writable,
                "{}: the owner receives the rent",
                g.instruction
            );
        }
    }

    #[test]
    fn no_manifest_can_declare_a_grounded_class() {
        for class in GROUNDED_CLASSES {
            assert!(!crate::manifest::RISK_CLASSES.contains(class));
        }
    }

    /// The published request schema lists the vocabulary the Core reads:
    /// every value it accepts is a canonical intent or a synonym of one, and
    /// every canonical intent is listed (Round 30 added withdraw, claim,
    /// burn and configure to both together).
    #[test]
    fn the_request_schema_lists_the_vocabulary() {
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("../../schemas/proposed-intent-v1.json")).unwrap();
        let listed: Vec<&str> = doc["properties"]["intent_type"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let canonical: Vec<&str> = crate::manifest::INTENT_DECLARES
            .iter()
            .map(|(i, _)| *i)
            .collect();
        for w in listed.iter().filter(|w| **w != "unknown") {
            assert!(
                canonical.contains(&crate::risk_engine::canonical_intent(w)),
                "the schema lists {w}, which is no canonical intent's word"
            );
        }
        for c in canonical {
            assert!(
                listed.contains(&c),
                "the schema omits the canonical intent {c}"
            );
        }
    }

    /// A grant lowers a manifest's tag; it never overrides what the NAME or
    /// the layout says (an authority word, a delegation grant, a required
    /// admin signer), which no grant may make an owner's own operation.
    #[test]
    fn no_grant_names_an_instruction_whose_name_or_layout_is_a_handover() {
        for g in GRANTS {
            let def = seed_def(g.program_id, g.instruction);
            assert!(
                !crate::manifest::names_an_authority_change(&def.name),
                "{}",
                def.name
            );
            assert!(
                !crate::manifest::names_a_delegation_grant(&def.name),
                "{}",
                def.name
            );
            assert!(!def.requires_an_admin_signature(), "{}", def.name);
        }
    }

    #[test]
    fn the_grants_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for g in GRANTS {
            assert!(seen.insert((g.program_id, g.instruction, g.intent)));
        }
    }

    #[test]
    fn an_associated_token_account_is_derived_not_assumed() {
        let owner = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
        let usdc = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let ata = {
            let o = Pubkey::from_base58(owner).unwrap();
            let t = Pubkey::from_base58(TOKEN_PROGRAMS[0]).unwrap();
            let m = Pubkey::from_base58(usdc).unwrap();
            find_program_address(
                &[o.as_bytes(), t.as_bytes(), m.as_bytes()],
                &Pubkey::from_base58(ATA_PROGRAM).unwrap(),
            )
            .unwrap()
            .0
            .to_base58()
        };
        assert!(is_associated_token_account(&ata, owner, usdc));
        // Someone else's, and garbage, are not.
        assert!(!is_associated_token_account(
            &ata,
            "11111111111111111111111111111112",
            usdc
        ));
        assert!(!is_associated_token_account("not-a-key", owner, usdc));
    }
}

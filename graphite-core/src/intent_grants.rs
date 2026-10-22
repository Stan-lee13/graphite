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
//! What a grant does NOT judge: amounts (how much is withdrawn, how high a
//! minimum out is), which is the signer's own business and the agent guard's
//! grounding (a withdrawal at a manipulated price is an economics question,
//! like a swap's minimum out). Round 32 (R30-G-1) judges one thing about them:
//! a withdrawal whose IDL gives it minimum outputs and whose every minimum is
//! zero accepts any amount out at all — whoever moves the pool in front of it
//! takes the difference — so its grant does not hold
//! ([`GrantOutcome::Unbounded`]) unless the operator allows it
//! (`GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS`). The minimums are read from the
//! instruction's own data at the offsets [`IntentGrant::minimum_outputs`]
//! names. Operations no grant covers keep their R2 refusal; a mint
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
    /// The instruction's minimum-output arguments, read from its data (Round
    /// 32): each a little-endian `u64` at a byte offset that counts the 8-byte
    /// discriminator. Empty when the IDL gives the instruction none.
    pub minimum_outputs: &'static [MinimumOutput],
    /// Where the account semantics come from.
    pub source: &'static str,
}

/// One minimum-output argument of a granted instruction: its IDL name and
/// where its little-endian `u64` starts in the instruction data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinimumOutput {
    pub name: &'static str,
    pub offset: usize,
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
        // args: liquidity u128 @8, amount_0_min u64 @24, amount_1_min u64 @32.
        minimum_outputs: &[
            MinimumOutput {
                name: "amount_0_min",
                offset: 24,
            },
            MinimumOutput {
                name: "amount_1_min",
                offset: 32,
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
        minimum_outputs: &[],
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
        // args: lp_token_amount u64 @8, minimum_token_0_amount u64 @16,
        // minimum_token_1_amount u64 @24.
        minimum_outputs: &[
            MinimumOutput {
                name: "minimum_token_0_amount",
                offset: 16,
            },
            MinimumOutput {
                name: "minimum_token_1_amount",
                offset: 24,
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
        minimum_outputs: &[],
        source: DLMM_IDL,
    },
    IntentGrant {
        program_id: METEORA_DLMM,
        instruction: "remove_liquidity2",
        intent: "withdraw",
        class: WITHDRAW_TO_OWNER,
        owner: "sender",
        grounding: DLMM_TO_SENDER,
        minimum_outputs: &[],
        source: DLMM_IDL,
    },
    IntentGrant {
        program_id: METEORA_DLMM,
        instruction: "remove_liquidity_by_range",
        intent: "withdraw",
        class: WITHDRAW_TO_OWNER,
        owner: "sender",
        grounding: DLMM_TO_SENDER,
        minimum_outputs: &[],
        source: DLMM_IDL,
    },
    IntentGrant {
        program_id: METEORA_DLMM,
        instruction: "remove_liquidity_by_range2",
        intent: "withdraw",
        class: WITHDRAW_TO_OWNER,
        owner: "sender",
        grounding: DLMM_TO_SENDER,
        minimum_outputs: &[],
        source: DLMM_IDL,
    },
    IntentGrant {
        program_id: METEORA_DLMM,
        instruction: "remove_all_liquidity",
        intent: "withdraw",
        class: WITHDRAW_TO_OWNER,
        owner: "sender",
        grounding: DLMM_TO_SENDER,
        minimum_outputs: &[],
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
        minimum_outputs: &[],
        source: DLMM_IDL,
    },
    IntentGrant {
        program_id: METEORA_DLMM,
        instruction: "claim_fee2",
        intent: "claim",
        class: CLAIM_TO_OWNER,
        owner: "sender",
        grounding: DLMM_TO_SENDER,
        minimum_outputs: &[],
        source: DLMM_IDL,
    },
    IntentGrant {
        program_id: METEORA_DLMM,
        instruction: "close_position",
        intent: "close",
        class: CLOSE_TO_OWNER,
        owner: "sender",
        grounding: DLMM_RENT_TO_SENDER,
        minimum_outputs: &[],
        source: "graphite-core/scripts/idls/meteora-dlmm.json close_position: the position's rent goes to rent_receiver, which the program does not constrain",
    },
    IntentGrant {
        program_id: METEORA_DLMM,
        instruction: "close_position2",
        intent: "close",
        class: CLOSE_TO_OWNER,
        owner: "sender",
        grounding: DLMM_RENT_TO_SENDER,
        minimum_outputs: &[],
        source: "graphite-core/scripts/idls/meteora-dlmm.json close_position2: rent to rent_receiver, unconstrained",
    },
    IntentGrant {
        program_id: METEORA_DLMM,
        instruction: "close_position_if_empty",
        intent: "close",
        class: CLOSE_TO_OWNER,
        owner: "sender",
        grounding: DLMM_RENT_TO_SENDER,
        minimum_outputs: &[],
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
        // args (scripts/out/onchain_idls/pAMMBay6…json): lp_token_amount_in
        // u64 @8, min_base_amount_out u64 @16, min_quote_amount_out u64 @24.
        minimum_outputs: &[
            MinimumOutput {
                name: "min_base_amount_out",
                offset: 16,
            },
            MinimumOutput {
                name: "min_quote_amount_out",
                offset: 24,
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
        minimum_outputs: &[],
        source: "Pump AMM IDL: user_volume_accumulator seeds [\"user_volume_accumulator\", user]; rent returned to user (signer, writable)",
    },
    IntentGrant {
        program_id: PUMP_FUN,
        instruction: "close_user_volume_accumulator",
        intent: "close",
        class: CLOSE_TO_OWNER,
        owner: "user",
        grounding: VOLUME_ACCUMULATOR,
        minimum_outputs: &[],
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
        minimum_outputs: &[],
        source: "SPL Token Burn: [account (w), mint (w), authority (s)]",
    },
    IntentGrant {
        program_id: TOKEN_PROGRAMS[0],
        instruction: "BurnChecked",
        intent: "burn",
        class: BURN_OWN,
        owner: "authority",
        grounding: BURN_FROM_OWN_ATA,
        minimum_outputs: &[],
        source: "SPL Token BurnChecked: [account (w), mint (w), authority (s)]",
    },
    IntentGrant {
        program_id: TOKEN_PROGRAMS[1],
        instruction: "Burn",
        intent: "burn",
        class: BURN_OWN,
        owner: "authority",
        grounding: BURN_FROM_OWN_ATA,
        minimum_outputs: &[],
        source: "Token-2022 Burn: [account (w), mint (w), authority (s)]",
    },
    IntentGrant {
        program_id: TOKEN_PROGRAMS[1],
        instruction: "BurnChecked",
        intent: "burn",
        class: BURN_OWN,
        owner: "authority",
        grounding: BURN_FROM_OWN_ATA,
        minimum_outputs: &[],
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
        minimum_outputs: &[],
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
    /// Round 32 (R30-G-1): every fact about the accounts holds, and every
    /// minimum output the instruction's data carries is zero (or the data
    /// does not carry them): a withdrawal that accepts any amount out. The
    /// grounded class is given, and the Core refuses the instruction
    /// (`RiskPattern::UnboundedWithdrawal`) with this reason.
    Unbounded { class: &'static str, reason: String },
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
/// the transaction's order) is judged by under `canonical_intent`, without the
/// instruction's data: a grant with minimum outputs is [`GrantOutcome::Unbounded`]
/// unless `allow_unbounded` (see [`ground_with`]).
pub fn ground(
    program_id: &str,
    def: &InstructionDef,
    canonical_intent: &str,
    accounts: &[String],
) -> GrantOutcome {
    ground_with(program_id, def, canonical_intent, accounts, None, false)
}

/// [`ground`] with the instruction's `data` (discriminator included), from
/// which a withdrawal's minimum outputs are read, and the operator's
/// `GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS` decision.
pub fn ground_with(
    program_id: &str,
    def: &InstructionDef,
    canonical_intent: &str,
    accounts: &[String],
    data: Option<&[u8]>,
    allow_unbounded: bool,
) -> GrantOutcome {
    let Some(grant) = grant_for(program_id, &def.name, canonical_intent) else {
        return GrantOutcome::NoGrant;
    };
    if let Err(why) = check(grant, def, accounts) {
        return GrantOutcome::Ungrounded(format!(
            "a '{}' intent declares {} only when the operation is the owner's own, and {why}",
            grant.intent, grant.instruction
        ));
    }
    if allow_unbounded {
        return GrantOutcome::Grounded(grant.class);
    }
    match unbounded(grant, data) {
        None => GrantOutcome::Grounded(grant.class),
        Some(why) => GrantOutcome::Unbounded {
            class: grant.class,
            reason: format!(
                "UnboundedWithdrawal: {} {why}; a withdrawal that accepts any amount out gives whoever moves the pool in front of it the difference (operator opt-out: GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS=1)",
                grant.instruction
            ),
        },
    }
}

/// Why `grant`'s minimum outputs do not bound the withdrawal, if they do not:
/// none can be read from `data`, or every one is zero. `None` for a grant with
/// no minimum outputs, or one at least one of whose minimums is non-zero.
fn unbounded(grant: &IntentGrant, data: Option<&[u8]>) -> Option<String> {
    if grant.minimum_outputs.is_empty() {
        return None;
    }
    let names = grant
        .minimum_outputs
        .iter()
        .map(|m| m.name)
        .collect::<Vec<_>>()
        .join(", ");
    let Some(data) = data else {
        return Some(format!(
            "carries no instruction data, so its minimum outputs ({names}) cannot be read"
        ));
    };
    let mut values = Vec::with_capacity(grant.minimum_outputs.len());
    for m in grant.minimum_outputs {
        let Some(bytes) = data.get(m.offset..m.offset + 8) else {
            return Some(format!(
                "carries {} byte(s) of instruction data, too few to hold `{}` at byte {}",
                data.len(),
                m.name,
                m.offset
            ));
        };
        let mut le = [0u8; 8];
        le.copy_from_slice(bytes);
        values.push(u64::from_le_bytes(le));
    }
    values
        .iter()
        .all(|v| *v == 0)
        .then(|| format!("sets every minimum output to zero ({names})"))
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
                if !seeds.contains(&owner_seed) {
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

    /// The IDL each grant with arguments was read from, by program.
    const GRANT_IDLS: &[(&str, &str)] = &[
        (RAYDIUM_CLMM, "scripts/idls/raydium_clmm.json"),
        (RAYDIUM_CPMM, "scripts/idls/raydium_cpmm.json"),
        (METEORA_DLMM, "scripts/idls/meteora-dlmm.json"),
        (
            PUMP_AMM,
            "scripts/out/onchain_idls/pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA.json",
        ),
    ];

    /// Round 32 (R30-G-1): every minimum output a grant reads is the IDL's
    /// own `u64` argument of that name, at the offset its preceding arguments
    /// put it (after the 8-byte discriminator); and every `u64` argument of a
    /// granted instruction whose name says it is a minimum is read. A grant
    /// that missed one would judge a withdrawal by half its bounds.
    #[test]
    fn the_minimum_outputs_are_the_idls_arguments_at_the_idls_offsets() {
        let size = |t: &serde_json::Value| match t.as_str() {
            Some("u8" | "i8" | "bool") => Some(1),
            Some("u16" | "i16") => Some(2),
            Some("u32" | "i32") => Some(4),
            Some("u64" | "i64") => Some(8),
            Some("u128" | "i128") => Some(16),
            _ => None,
        };
        let mut read = 0;
        for (program, file) in GRANT_IDLS {
            let path = format!("{}/{file}", env!("CARGO_MANIFEST_DIR"));
            let idl: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            for g in GRANTS.iter().filter(|g| g.program_id == *program) {
                let ix = idl["instructions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|i| i["name"] == g.instruction)
                    .unwrap_or_else(|| panic!("{file} has no {}", g.instruction));
                let mut offset = Some(8usize);
                let mut minimums = Vec::new();
                for arg in ix["args"].as_array().unwrap() {
                    let name = arg["name"].as_str().unwrap();
                    if arg["type"] == "u64" && name.contains("min") {
                        minimums.push((name, offset));
                    }
                    offset = offset.zip(size(&arg["type"])).map(|(o, s)| o + s);
                }
                let declared: Vec<(&str, Option<usize>)> = g
                    .minimum_outputs
                    .iter()
                    .map(|m| (m.name, Some(m.offset)))
                    .collect();
                assert_eq!(declared, minimums, "{} {}", file, g.instruction);
                read += declared.len();
            }
        }
        assert_eq!(
            read, 6,
            "CLMM decrease_liquidity_v2, CPMM and Pump AMM withdraw"
        );
    }

    #[test]
    fn a_withdrawal_is_unbounded_only_when_every_minimum_is_zero_or_unreadable() {
        let g = grant_for(RAYDIUM_CPMM, "withdraw", "withdraw").unwrap();
        let data = |a: u64, b: u64| {
            let mut d = vec![0xB7; 8];
            d.extend_from_slice(&5u64.to_le_bytes());
            d.extend_from_slice(&a.to_le_bytes());
            d.extend_from_slice(&b.to_le_bytes());
            d
        };
        assert!(unbounded(g, Some(&data(0, 0))).is_some());
        assert!(unbounded(g, Some(&data(0, 1))).is_none());
        assert!(unbounded(g, Some(&data(1, 0))).is_none());
        assert!(unbounded(g, Some(&data(0, 1)[..31])).is_some(), "short");
        assert!(unbounded(g, None).is_some(), "no data");
        // A grant with no minimum outputs is never unbounded.
        let close = grant_for(RAYDIUM_CLMM, "close_position", "close").unwrap();
        assert!(unbounded(close, None).is_none());
    }
}

//! L4 — real pre/post account state diffing.
//!
//! ARCHITECTURE.md 3.12 specifies L4 as "diff pre/post account state against
//! declared intent". Until now the layer could only inspect the *shape* of the
//! instruction — how many accounts were writable, whether a signer was
//! present — and compare that against the English prose in a manifest's
//! `expected_state_changes`. That is a consistency check on the request, not a
//! check on what the transaction actually does.
//!
//! This module supplies the missing half: given the account state before the
//! transaction and the account state after it, compute what actually changed
//! and test that against what the protocol manifest declared would change.
//!
//! # The rule that makes this useful
//!
//! Observed-but-undeclared is a failure. Declared-but-unobserved is a note.
//!
//! A manifest is a promise about the effects of an instruction. If the diff
//! shows an effect the manifest never promised — an owner reassignment during
//! what claims to be a swap, a delegate granted during what claims to be a
//! transfer, a mint supply increase during a stake — the transaction is doing
//! something the protocol did not describe, and that is precisely the class of
//! attack a gate between an agent and a wallet exists to stop. The reverse,
//! a declared effect that did not materialise, is usually a legitimate no-op
//! (a zero-amount transfer, an already-initialised account) and only ever
//! produces a warning.
//!
//! # Provenance (Constitution P5)
//!
//! Simulation is evidence, never ground truth, and a diff supplied by the
//! caller is a claim about evidence rather than the evidence itself. So a
//! caller-supplied diff can *fail* this layer but can never *pass* it: with no
//! findings it yields Inconclusive, not Passed. Only a diff Graphite built
//! itself from `simulateTransaction` can certify a clean result. This is the
//! same asymmetry the simulation-integrity layer applies to compute usage, and
//! for the same reason — an attacker who controls the numbers must not be able
//! to manufacture a clean verdict, but nobody manufactures a self-incriminating
//! one.
//!
//! # Lamport conservation
//!
//! Solana conserves lamports: across a whole transaction, the sum of every
//! balance change equals the negative of the fee. When a diff claims to cover
//! every writable account, that identity is checkable — and a diff that fails
//! it is either incomplete or fabricated. This catches a spoofed diff without
//! needing to trust anything in it.

use serde::{Deserialize, Serialize};

use crate::account_resolution::ResolvedAccount;

/// SPL Token program (the classic one).
pub const SPL_TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// SPL Token-2022 program.
pub const SPL_TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
/// The System program, which owns every account that holds only lamports.
pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";

/// Canonical size of an SPL token account. Token-2022 accounts are this long
/// plus an account-type byte and any extensions.
const TOKEN_ACCOUNT_LEN: usize = 165;
/// Canonical size of an SPL mint. Token-2022 mints extend past this.
const MINT_LEN: usize = 82;
/// Token-2022 writes an account-type discriminator immediately after the base
/// layout: 1 = Mint, 2 = Account. This is what makes an extended mint
/// distinguishable from an extended token account, both of which can be longer
/// than 165 bytes.
const T22_TYPE_OFFSET: usize = TOKEN_ACCOUNT_LEN;
const T22_TYPE_MINT: u8 = 1;
const T22_TYPE_ACCOUNT: u8 = 2;

/// An all-zero pubkey means "none" in every COption-style field on-chain.
const NULL_PUBKEY: &str = "11111111111111111111111111111111";

/// How `ExtensionScan::malformed` begins when what could not be read is the
/// BASE token layout rather than the extension region (F8). The finding is
/// then `TokenLayoutUndecodable`, which also applies to classic SPL Token.
const TOKEN_LAYOUT_UNDECODABLE: &str = "the base token layout does not decode: ";

/// Where a diff came from. Only `RpcSimulated` may certify a clean layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DiffProvenance {
    /// Graphite built this diff itself: pre-state from `getMultipleAccounts`,
    /// post-state from `simulateTransaction` with an `accounts` request.
    RpcSimulated,
    /// The caller supplied the diff. Usable as a signal, never as a
    /// certification (P5). This is the default because an absent or
    /// unrecognised provenance must never be read as Graphite's own
    /// measurement — a deserialized diff missing the field would otherwise
    /// arrive claiming RPC authority.
    #[default]
    CallerSupplied,
}

/// Decoded view of an SPL token account. Both Token and Token-2022 share this
/// base layout, so one decoder serves both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TokenAccountView {
    pub mint: String,
    pub owner: String,
    pub amount: u64,
    pub delegate: Option<String>,
    pub delegated_amount: u64,
    /// 0 = uninitialized, 1 = initialized, 2 = frozen.
    pub state: u8,
    pub close_authority: Option<String>,
}

impl TokenAccountView {
    pub fn is_frozen(&self) -> bool {
        self.state == 2
    }
}

/// Decoded view of an SPL mint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MintView {
    pub mint_authority: Option<String>,
    pub supply: u64,
    pub decimals: u8,
    pub freeze_authority: Option<String>,
}

/// The state of one account at one point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AccountSnapshot {
    pub pubkey: String,
    pub lamports: u64,
    pub owner: String,
    pub data_len: usize,
    /// Present when the account decodes as an SPL token account.
    #[serde(default)]
    pub token: Option<TokenAccountView>,
    /// Present when the account decodes as an SPL mint.
    #[serde(default)]
    pub mint: Option<MintView>,
    /// Token-2022 extensions attached to this account, or why they could not
    /// be read.
    ///
    /// Detected, named and classified. A clean scan means no extension was
    /// found, which is not the same as a claim that the account is simple; a
    /// malformed scan means the account cannot be reasoned about. Only the
    /// transfer-fee pair is MODELLED (Round 20) — see `transfer_fee_withheld`
    /// and `transfer_fee_config` — and every other extension that can alter a
    /// transfer still blocks.
    ///
    /// Round 29 (F8): for an account of EITHER token program whose data has
    /// the layout of a token account or a mint but does not decode as one (a
    /// COption tag other than 0 or 1, a state or `is_initialized` byte out of
    /// range), `malformed` says so, prefixed "the base token layout does not
    /// decode: ", and the layer reports `TokenLayoutUndecodable`.
    #[serde(default)]
    pub extensions: ExtensionScan,
    /// `TransferFeeAmount.withheld_amount` of a Token-2022 token account: the
    /// fees withheld in this account and not yet harvested. `None` when the
    /// account carries no such extension, or carries one this build could not
    /// read exactly (a wrong length, a duplicate entry, a malformed region) —
    /// and an account whose withheld amount cannot be read is one whose fee
    /// cannot be modelled.
    #[serde(default)]
    pub transfer_fee_withheld: Option<u64>,
    /// `TransferFeeConfig` of a Token-2022 mint, read exactly or not at all.
    #[serde(default)]
    pub transfer_fee_config: Option<TransferFeeConfigView>,
    /// The other Token-2022 extension values the model reads (Round 21), or
    /// `None` when one of them is present and could not be read exactly.
    #[serde(default)]
    pub token2022_powers: Option<Token2022Powers>,
    /// SHA-256 of the account's data, hex (A2-05, 2026-09-29 audit). The
    /// snapshot kept the length and the decoded token views only, so a
    /// rewrite of any other data — a stake account's withdrawer, a program's
    /// upgrade authority, any program's own state — compared equal and was
    /// read as "observed unchanged". `None` for a snapshot built without data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_sha256: Option<String>,
    /// Whether the account is executable (A2-05).
    #[serde(default)]
    pub executable: bool,
    /// The authorities a NATIVE account records in its data, decoded where
    /// the layout is fixed: a Stake account's staker, withdrawer and lockup
    /// custodian, and a program's upgrade authority in its ProgramData
    /// account (A2-05). Empty for every other account.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub native_authorities: Vec<(String, String)>,
}

/// `ExtensionType` discriminants the model reads beyond the transfer fee.
const EXT_MINT_CLOSE_AUTHORITY: u16 = 3;
const EXT_CONFIDENTIAL_TRANSFER_MINT: u16 = 4;
const EXT_CONFIDENTIAL_TRANSFER_ACCOUNT: u16 = 5;
const EXT_PERMANENT_DELEGATE: u16 = 12;
const EXT_TRANSFER_HOOK: u16 = 14;
const EXT_TRANSFER_HOOK_ACCOUNT: u16 = 15;
const EXT_CONFIDENTIAL_TRANSFER_FEE_CONFIG: u16 = 16;
const EXT_CONFIDENTIAL_TRANSFER_FEE_AMOUNT: u16 = 17;
const EXT_CONFIDENTIAL_MINT_BURN: u16 = 24;
const CONFIDENTIAL_EXTENSIONS: [u16; 5] = [
    EXT_CONFIDENTIAL_TRANSFER_MINT,
    EXT_CONFIDENTIAL_TRANSFER_ACCOUNT,
    EXT_CONFIDENTIAL_TRANSFER_FEE_CONFIG,
    EXT_CONFIDENTIAL_TRANSFER_FEE_AMOUNT,
    EXT_CONFIDENTIAL_MINT_BURN,
];
/// Token-2022 instruction families that operate on confidential balances:
/// ConfidentialTransfer (27), ConfidentialTransferFee (37),
/// ConfidentialMintBurn (42).
const T22_CONFIDENTIAL_INSTRUCTIONS: [u8; 3] = [27, 37, 42];

/// Token-2022 extension values beyond the transfer fee (Round 21).
///
/// Each field is `None` when the extension is absent, `Some(None)` when it is
/// present and names nobody, `Some(Some(key))` when it names a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Token2022Powers {
    /// Mint: who can move or burn any holder's tokens without the holder.
    pub permanent_delegate: Option<Option<String>>,
    /// Mint: who can close the mint once its supply is zero.
    pub close_authority: Option<Option<String>>,
    /// Mint: the program every transfer invokes.
    pub transfer_hook_program: Option<Option<String>>,
    /// SHA-256 over the confidential-transfer extension values present, so a
    /// change to encrypted balances is visible without decoding them.
    pub confidential_digest: Option<String>,
    /// W19 (external review): the authority the other authority-bearing mint
    /// extensions keep in their first 32 bytes — transfer hook, interest
    /// rate, metadata and group pointers, token metadata and group update
    /// authority, scaled UI amount, pause, confidential configuration — as
    /// (extension, key or none), in extension order. A change to any of them
    /// is a change of who controls the mint.
    #[serde(default)]
    pub extension_authorities: Vec<(u16, Option<String>)>,
    /// Pausable: whether the mint is paused (every holder's transfers stop).
    #[serde(default)]
    pub paused: Option<bool>,
}

/// Mint extensions whose value starts with an `OptionalNonZeroPubkey`
/// authority (spl-token-2022 `ExtensionType`): ConfidentialTransferMint (4),
/// InterestBearingConfig (10), TransferHook (14), ConfidentialTransferFeeConfig
/// (16), MetadataPointer (18), TokenMetadata (19, update authority),
/// GroupPointer (20), TokenGroup (21, update authority), GroupMemberPointer
/// (22), ScaledUiAmount (25), Pausable (26).
const EXT_AUTHORITY_FIRST: [u16; 11] = [4, 10, 14, 16, 18, 19, 20, 21, 22, 25, 26];
const EXT_PAUSABLE: u16 = 26;
/// Every extension `Token2022Powers` reads an authority (or the paused flag)
/// out of: the authority-first ones, MintCloseAuthority and PermanentDelegate
/// (F5).
const EXT_AUTHORITY_BEARING: [u16; 13] = [3, 4, 10, 12, 14, 16, 18, 19, 20, 21, 22, 25, 26];

/// Read the extension values in `Token2022Powers`, exactly or not at all.
pub fn decode_token2022_powers(data: &[u8]) -> Option<Token2022Powers> {
    use sha2::{Digest, Sha256};
    let scan = detect_token2022_extensions(data);
    if scan.malformed.is_some() {
        return None;
    }
    let present = |d: u16| scan.found.iter().any(|e| e.discriminant == d);
    let key32 = |d: u16| -> Option<Option<Option<String>>> {
        if !present(d) {
            return Some(None);
        }
        let v = single_extension_value(data, d)?;
        if v.len() != 32 {
            return None;
        }
        Some(Some(optional_nonzero_pubkey(v, 0)?))
    };
    let transfer_hook_program = if present(EXT_TRANSFER_HOOK) {
        let v = single_extension_value(data, EXT_TRANSFER_HOOK)?;
        if v.len() != 64 {
            return None;
        }
        Some(optional_nonzero_pubkey(v, 32)?)
    } else {
        None
    };
    let mut hasher = Sha256::new();
    let mut any_confidential = false;
    for d in CONFIDENTIAL_EXTENSIONS {
        if present(d) {
            let v = single_extension_value(data, d)?;
            hasher.update(d.to_le_bytes());
            hasher.update((v.len() as u32).to_le_bytes());
            hasher.update(v);
            any_confidential = true;
        }
    }
    let mut extension_authorities = Vec::new();
    for d in EXT_AUTHORITY_FIRST {
        if present(d) {
            let v = single_extension_value(data, d)?;
            extension_authorities.push((d, optional_nonzero_pubkey(v, 0)?));
        }
    }
    let paused = if present(EXT_PAUSABLE) {
        Some(*single_extension_value(data, EXT_PAUSABLE)?.get(32)? != 0)
    } else {
        None
    };
    Some(Token2022Powers {
        permanent_delegate: key32(EXT_PERMANENT_DELEGATE)?,
        close_authority: key32(EXT_MINT_CLOSE_AUTHORITY)?,
        transfer_hook_program,
        confidential_digest: any_confidential.then(|| hex::encode(hasher.finalize())),
        extension_authorities,
        paused,
    })
}

// -- Token-2022 TransferFee: the one extension pair that is modelled ---------

/// `spl_token_2022::extension::transfer_fee::MAX_FEE_BASIS_POINTS`.
pub const MAX_FEE_BASIS_POINTS: u16 = 10_000;
/// `ExtensionType::TransferFeeConfig`, on a mint.
const EXT_TRANSFER_FEE_CONFIG: u16 = 1;
/// `ExtensionType::TransferFeeAmount`, on a token account.
const EXT_TRANSFER_FEE_AMOUNT: u16 = 2;
/// `TransferFeeConfig`: config authority (32) + withdraw-withheld authority
/// (32) + withheld amount (8) + older fee (18) + newer fee (18).
const TRANSFER_FEE_CONFIG_LEN: usize = 108;
/// `TransferFeeAmount`: withheld amount (8).
const TRANSFER_FEE_AMOUNT_LEN: usize = 8;

/// One epoch's transfer fee: `spl_token_2022::extension::transfer_fee::TransferFee`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TransferFeeSchedule {
    /// First epoch in which this schedule applies.
    pub epoch: u64,
    /// The fee on one transfer never exceeds this, in base units.
    pub maximum_fee: u64,
    /// The fee rate, in hundredths of a percent.
    pub basis_points: u16,
}

impl TransferFeeSchedule {
    /// The fee Token-2022 charges on one transfer of `amount`, exactly as
    /// `TransferFee::calculate_fee` computes it: the rate applied to the gross
    /// amount, rounded UP, capped at `maximum_fee`; zero for a zero rate or a
    /// zero amount. `None` for a rate above 100%, which the program refuses to
    /// set and which is therefore not a schedule at all.
    pub fn fee(&self, amount: u64) -> Option<u64> {
        if self.basis_points > MAX_FEE_BASIS_POINTS {
            return None;
        }
        if self.basis_points == 0 || amount == 0 {
            return Some(0);
        }
        let numerator = u128::from(amount) * u128::from(self.basis_points);
        let raw = numerator.div_ceil(u128::from(MAX_FEE_BASIS_POINTS));
        Some(u64::try_from(raw).ok()?.min(self.maximum_fee))
    }

    fn describe(&self) -> String {
        format!(
            "{} bps, at most {} per transfer, from epoch {}",
            self.basis_points, self.maximum_fee, self.epoch
        )
    }
}

/// A mint's `TransferFeeConfig`.
///
/// Two schedules because a change is never immediate: `SetTransferFee`
/// writes the new schedule as `newer` with an epoch two epochs ahead, and
/// `older` applies until then. Which one a transfer paid is therefore a fact
/// about the epoch it ran in, and a transaction verified in one epoch can
/// land in the next.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TransferFeeConfigView {
    /// Who may change the schedule. `None` means nobody can.
    pub config_authority: Option<String>,
    /// Who may withdraw withheld fees. `None` means nobody can.
    pub withdraw_withheld_authority: Option<String>,
    /// Fees harvested into the mint and not yet withdrawn.
    pub withheld_amount: u64,
    pub older: TransferFeeSchedule,
    pub newer: TransferFeeSchedule,
}

impl TransferFeeConfigView {
    /// The same config with the withheld pool ignored — the part that decides
    /// what a transfer costs and who controls it.
    fn terms(
        &self,
    ) -> (
        Option<&str>,
        Option<&str>,
        TransferFeeSchedule,
        TransferFeeSchedule,
    ) {
        (
            self.config_authority.as_deref(),
            self.withdraw_withheld_authority.as_deref(),
            self.older,
            self.newer,
        )
    }

    /// The schedule Token-2022 applies to a transfer executed in `epoch`,
    /// exactly as `TransferFeeConfig::get_epoch_fee` chooses it: the newer
    /// schedule from its epoch on, the older one before.
    pub fn applicable_at(&self, epoch: u64) -> TransferFeeSchedule {
        if epoch >= self.newer.epoch {
            self.newer
        } else {
            self.older
        }
    }
}

/// One Token-2022 instruction the simulator executed, with its accounts
/// resolved to addresses (Round 21).
///
/// Built by the pipeline from the transaction's own instructions and the
/// simulation's `innerInstructions` — never from a request. It is how the fee
/// model tells several transfers into one account apart, and how it follows
/// a withdrawal of withheld fees: the diff says where value ended up, the
/// executed instructions say how it got there, and the model requires the
/// two to agree exactly.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecutedTokenInstruction {
    /// Where it ran, for the verdict: "instruction #2", "a CPI under
    /// instruction #1".
    pub position: String,
    pub accounts: Vec<String>,
    pub data: Vec<u8>,
}

/// Which fee schedule a transaction paid in its simulation (Round 21), and
/// how it expires.
///
/// A mint carries two schedules and the epoch decides between them. The
/// simulation ran in one epoch, which Graphite reads from the RPC — that is
/// an observation. Where the transaction LANDS is not: Round 21 bounded it
/// with an assumed 9,000-slot margin, and Round 22 removed the assumption. A
/// blockhash is valid for 150 BLOCKS, epochs are counted in SLOTS, and a
/// skipped slot has no block, so no number of slots bounds when a blockhash
/// transaction can still land. A pending schedule is therefore always one the
/// transaction can pay, and is judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeEpochContext {
    /// The epoch the simulation executed in.
    pub simulated_epoch: u64,
    /// Whether the transaction advances a durable nonce instead of naming a
    /// recent blockhash — it does not expire at all. Only changes how the
    /// verdict words the reach of a pending schedule.
    pub durable_nonce: bool,
}

/// An `OptionalNonZeroPubkey`: 32 bytes, all-zero meaning none.
fn optional_nonzero_pubkey(data: &[u8], offset: usize) -> Option<Option<String>> {
    let bytes = data.get(offset..offset + 32)?;
    Some(if bytes.iter().all(|b| *b == 0) {
        None
    } else {
        Some(bs58::encode(bytes).into_string())
    })
}

fn transfer_fee_schedule(data: &[u8], offset: usize) -> Option<TransferFeeSchedule> {
    Some(TransferFeeSchedule {
        epoch: u64_at(data, offset)?,
        maximum_fee: u64_at(data, offset + 8)?,
        basis_points: u16::from_le_bytes(data.get(offset + 16..offset + 18)?.try_into().ok()?),
    })
}

/// The value of exactly one extension entry of `discriminant`, or `None`.
///
/// `None` covers every case in which the value cannot be trusted to be THE
/// value: the region does not walk cleanly, the entry is absent, or it
/// appears more than once. A model that picked the first of two withheld
/// amounts would be choosing which one to believe.
fn single_extension_value(data: &[u8], discriminant: u16) -> Option<&[u8]> {
    if data.len() <= T22_TLV_START {
        return None;
    }
    if !matches!(
        data.get(T22_TYPE_OFFSET),
        Some(&T22_TYPE_ACCOUNT) | Some(&T22_TYPE_MINT)
    ) {
        return None;
    }
    let mut found: Option<&[u8]> = None;
    let mut offset = T22_TLV_START;
    while offset < data.len() {
        if offset + 4 > data.len() {
            // M11: a short tail ends the region exactly when the program's
            // own walk ends there; see `short_tlv_tail_ends_region`.
            if short_tlv_tail_ends_region(&data[offset..]) {
                break;
            }
            return None;
        }
        let d = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let length = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;
        if d == 0 {
            break;
        }
        let value = data.get(offset + 4..offset + 4 + length)?;
        if d == discriminant {
            if found.is_some() {
                return None;
            }
            found = Some(value);
        }
        offset += 4 + length;
    }
    found
}

/// `TransferFeeAmount.withheld_amount`, when the account carries exactly one
/// entry of exactly the right length.
pub fn decode_transfer_fee_withheld(data: &[u8]) -> Option<u64> {
    if data.get(T22_TYPE_OFFSET) != Some(&T22_TYPE_ACCOUNT) {
        return None;
    }
    let value = single_extension_value(data, EXT_TRANSFER_FEE_AMOUNT)?;
    if value.len() != TRANSFER_FEE_AMOUNT_LEN {
        return None;
    }
    u64_at(value, 0)
}

/// `TransferFeeConfig`, when the mint carries exactly one entry of exactly
/// the right length and both schedules are schedules the program could set.
pub fn decode_transfer_fee_config(data: &[u8]) -> Option<TransferFeeConfigView> {
    if data.get(T22_TYPE_OFFSET) != Some(&T22_TYPE_MINT) {
        return None;
    }
    let v = single_extension_value(data, EXT_TRANSFER_FEE_CONFIG)?;
    if v.len() != TRANSFER_FEE_CONFIG_LEN {
        return None;
    }
    let config = TransferFeeConfigView {
        config_authority: optional_nonzero_pubkey(v, 0)?,
        withdraw_withheld_authority: optional_nonzero_pubkey(v, 32)?,
        withheld_amount: u64_at(v, 64)?,
        older: transfer_fee_schedule(v, 72)?,
        newer: transfer_fee_schedule(v, 90)?,
    };
    if config.older.basis_points > MAX_FEE_BASIS_POINTS
        || config.newer.basis_points > MAX_FEE_BASIS_POINTS
    {
        return None;
    }
    Some(config)
}

impl AccountSnapshot {
    /// Decode raw account bytes into a snapshot, including the SPL views when
    /// the owner and layout say the data is a token account or a mint.
    ///
    /// Anything that does not decode cleanly stays `None` rather than being
    /// guessed at — a wrong decode here would produce a wrong finding, which
    /// is worse than no finding.
    pub fn from_raw(pubkey: &str, lamports: u64, owner: &str, data: &[u8]) -> Self {
        let is_token_program = owner == SPL_TOKEN_PROGRAM || owner == SPL_TOKEN_2022_PROGRAM;
        let (token, mint) = if is_token_program {
            (decode_token_account(data), decode_mint(data))
        } else {
            (None, None)
        };
        let is_token_2022 = owner == SPL_TOKEN_2022_PROGRAM;
        // F8: data with the layout of a token account or a mint whose fields
        // do not decode is recorded as unreadable, not as an account with no
        // token view — the latter is what an ordinary non-token account
        // looks like, and none of the authority checks would see it.
        let layout_error = if is_token_program {
            token_layout_error(data)
        } else {
            None
        };
        Self {
            pubkey: pubkey.to_string(),
            lamports,
            owner: owner.to_string(),
            data_len: data.len(),
            token,
            mint,
            extensions: if let Some(why) = layout_error {
                ExtensionScan {
                    found: Vec::new(),
                    malformed: Some(format!("{TOKEN_LAYOUT_UNDECODABLE}{why}")),
                }
            } else if is_token_2022 {
                detect_token2022_extensions(data)
            } else {
                // Classic SPL Token has no extension region. Looking for one
                // would read whatever follows a 165-byte account as TLV.
                ExtensionScan::default()
            },
            transfer_fee_withheld: if is_token_2022 {
                decode_transfer_fee_withheld(data)
            } else {
                None
            },
            transfer_fee_config: if is_token_2022 {
                decode_transfer_fee_config(data)
            } else {
                None
            },
            token2022_powers: if is_token_2022 {
                decode_token2022_powers(data)
            } else {
                None
            },
            data_sha256: Some({
                use sha2::Digest;
                hex::encode(sha2::Sha256::digest(data))
            }),
            executable: false,
            native_authorities: native_authorities(owner, data),
        }
    }

    /// The same snapshot with the account's executable flag (A2-05).
    pub fn with_executable(mut self, executable: bool) -> Self {
        self.executable = executable;
        self
    }
}

/// The authorities a native account keeps at fixed offsets in its data
/// (A2-05, 2026-09-29 audit).
///
/// - Stake (`StakeStateV2`, u32 tag 1 Initialized or 2 Stake): `Meta` =
///   rent-exempt reserve (u64, 4..12), `Authorized` { staker 12..44,
///   withdrawer 44..76 }, `Lockup` { unix_timestamp 76..84, epoch 84..92,
///   custodian 92..124 }.
/// - BPF Upgradeable Loader `ProgramData` (u32 tag 3): slot (u64, 4..12),
///   `Option<Pubkey>` upgrade authority (tag byte 12, key 13..45), then the
///   program's code, recorded by its SHA-256 so a rewrite under an unchanged
///   authority shows. `Buffer` (u32 tag 1): `Option<Pubkey>` authority (tag
///   byte 4, key 5..37).
///
/// W19 (external review) added the rest, each a standing power over the
/// account that no lamport or token field shows:
/// - the stake lockup itself (unix_timestamp, epoch), not only its custodian;
/// - a System nonce account (80 bytes: version u32, state u32 = 1
///   Initialized, authority 8..40), whose authority can withdraw it;
/// - a vote account (`VoteState` u32 tag 1 V1_14_11 or 2 Current:
///   node 4..36, authorized withdrawer 36..68; tag 3 V4 adds the inflation
///   rewards and block revenue collectors at 68..100 and 100..132, and any
///   other version is recorded by its data's SHA-256 — Round 29, F6);
/// - an address lookup table (u32 type 1, `Option<Pubkey>` authority: tag
///   byte 21, key 22..54).
///
/// Anything shorter than its layout, or another state, decodes to nothing.
fn native_authorities(owner: &str, data: &[u8]) -> Vec<(String, String)> {
    let key = |r: std::ops::Range<usize>| data.get(r).map(|b| bs58::encode(b).into_string());
    let tag = data
        .get(0..4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let mut out = Vec::new();
    match (owner, tag) {
        ("Stake11111111111111111111111111111111111111", Some(1 | 2)) => {
            if let (Some(staker), Some(withdrawer), Some(custodian), Some(ts), Some(epoch)) = (
                key(12..44),
                key(44..76),
                key(92..124),
                data.get(76..84)
                    .map(|b| i64::from_le_bytes(b.try_into().expect("8 bytes"))),
                data.get(84..92)
                    .map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes"))),
            ) {
                out.push(("stake staker".to_string(), staker));
                out.push(("stake withdrawer".to_string(), withdrawer));
                out.push(("stake lockup custodian".to_string(), custodian));
                out.push((
                    "stake lockup".to_string(),
                    format!("unix {ts}, epoch {epoch}"),
                ));
            }
        }
        ("BPFLoaderUpgradeab1e11111111111111111111111", Some(3)) => {
            match data.get(12) {
                Some(0) => out.push(("program upgrade authority".to_string(), "none".to_string())),
                Some(1) => {
                    if let Some(k) = key(13..45) {
                        out.push(("program upgrade authority".to_string(), k));
                    }
                }
                _ => {}
            }
            if let Some(code) = data.get(45..) {
                use sha2::Digest;
                out.push((
                    "program code (sha256)".to_string(),
                    hex::encode(sha2::Sha256::digest(code)),
                ));
            }
        }
        ("BPFLoaderUpgradeab1e11111111111111111111111", Some(1)) => match data.get(4) {
            Some(0) => out.push(("buffer authority".to_string(), "none".to_string())),
            Some(1) => {
                if let Some(k) = key(5..37) {
                    out.push(("buffer authority".to_string(), k));
                }
            }
            _ => {}
        },
        ("11111111111111111111111111111111", Some(0 | 1))
            if data.len() == 80 && data.get(4..8) == Some(&1u32.to_le_bytes()[..]) =>
        {
            if let Some(k) = key(8..40) {
                out.push(("nonce authority".to_string(), k));
            }
        }
        ("Vote111111111111111111111111111111111111111", Some(1 | 2)) => {
            if let Some(k) = key(36..68) {
                out.push(("vote authorized withdrawer".to_string(), k));
            }
        }
        // Round 29 (audit 2026-10-20, F6): `VoteStateVersions::V4` (tag 3,
        // SIMD-0185) keeps `node_pubkey` (4..36) and `authorized_withdrawer`
        // (36..68) where V3 has them, then adds the two accounts the
        // validator's revenue is paid to: `inflation_rewards_collector`
        // (68..100) and `block_revenue_collector` (100..132). It was not
        // decoded, so a withdrawer handed over in a V4 account was invisible.
        ("Vote111111111111111111111111111111111111111", Some(3)) => {
            if let (Some(withdrawer), Some(inflation), Some(revenue)) =
                (key(36..68), key(68..100), key(100..132))
            {
                out.push(("vote authorized withdrawer".to_string(), withdrawer));
                out.push(("vote inflation rewards collector".to_string(), inflation));
                out.push(("vote block revenue collector".to_string(), revenue));
            } else {
                out.push(vote_state_undecodable(data));
            }
        }
        // Any other vote-state version (V0_23_5, or one newer than this
        // build) is not decoded, and not taken as having no authorities
        // either: its whole data is recorded, so a vote account whose bytes
        // changed is a finding the manifest has to account for (F6).
        ("Vote111111111111111111111111111111111111111", _) if !data.is_empty() => {
            out.push(vote_state_undecodable(data));
        }
        ("AddressLookupTab1e1111111111111111111111111", Some(1)) => match data.get(21) {
            Some(0) => out.push(("lookup table authority".to_string(), "none".to_string())),
            Some(1) => {
                if let Some(k) = key(22..54) {
                    out.push(("lookup table authority".to_string(), k));
                }
            }
            _ => {}
        },
        _ => {}
    }
    out
}

/// The stand-in authority of a vote account this build cannot decode: its
/// data's SHA-256, so any change to it compares unequal (F6).
fn vote_state_undecodable(data: &[u8]) -> (String, String) {
    use sha2::Digest;
    (
        "vote state (version not decoded; sha256)".to_string(),
        hex::encode(sha2::Sha256::digest(data)),
    )
}

/// How an authority that may or may not exist is written in a finding.
///
/// `None` is a real on-chain state — a revoked mint authority, a mint that
/// can never be frozen — and printing it as an empty string would read as a
/// missing value rather than as the fact it is.
fn authority_label(key: &Option<String>) -> &str {
    key.as_deref().unwrap_or("none")
}

fn pubkey_at(data: &[u8], offset: usize) -> Option<String> {
    let bytes = data.get(offset..offset + 32)?;
    Some(bs58::encode(bytes).into_string())
}

/// An on-chain COption<Pubkey>: a 4-byte little-endian tag followed by the key.
/// Tag 0 is None and tag 1 is Some. A Some whose key is all zeroes is still
/// treated as None, because that is what it means in practice.
///
/// Round 29 (audit 2026-10-20, F8): every other tag is UNDECODABLE, the outer
/// `Err`. `COption::unpack` in spl-token refuses tags 2..=u32::MAX, so no
/// account the program wrote carries one; a tag of 7 used to read as Some,
/// and the 32 bytes after it — whatever they were — as a delegate, a close
/// authority, a mint authority. What only a broken or hostile source can
/// produce is refused, never interpreted.
fn coption_pubkey(data: &[u8], tag_offset: usize) -> Result<Option<String>, String> {
    let tag = data
        .get(tag_offset..tag_offset + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| format!("the COption at offset {tag_offset} is cut short"))?;
    match tag {
        0 => Ok(None),
        1 => {
            let key = pubkey_at(data, tag_offset + 4)
                .ok_or_else(|| format!("the COption at offset {tag_offset} is cut short"))?;
            Ok(if key == NULL_PUBKEY { None } else { Some(key) })
        }
        other => Err(format!(
            "the COption tag at offset {tag_offset} is {other}; only 0 (None) and 1 (Some) are valid"
        )),
    }
}

/// `spl_token::state::Multisig::LEN`. Token-2022 pads an extended account
/// that would be exactly this long by two bytes (`adjust_len_for_multisig`),
/// so data of this length owned by either token program is a Multisig and
/// never an account or a mint — whatever byte 165 happens to hold.
const MULTISIG_LEN: usize = 355;

fn u64_at(data: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        data.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

/// Decode the 165-byte SPL token account layout, shared by Token and
/// Token-2022. Returns `None` when the data is not a token account, or has
/// the layout of one and does not decode (`token_layout_error` says why).
pub fn decode_token_account(data: &[u8]) -> Option<TokenAccountView> {
    decode_token_account_checked(data).ok().flatten()
}

/// `Ok(None)`: not a token account (wrong length or type byte, or
/// uninitialized). `Err`: the layout says token account and a field does not
/// decode (F8).
fn decode_token_account_checked(data: &[u8]) -> Result<Option<TokenAccountView>, String> {
    if data.len() < TOKEN_ACCOUNT_LEN || data.len() == MULTISIG_LEN {
        return Ok(None);
    }
    // A Token-2022 account longer than the base layout carries an explicit
    // type byte; anything longer that does NOT say "account" is a mint or an
    // unknown extension, and must not be decoded as an account.
    if data.len() > TOKEN_ACCOUNT_LEN && data.get(T22_TYPE_OFFSET) != Some(&T22_TYPE_ACCOUNT) {
        return Ok(None);
    }
    let short = || "the token account layout is cut short".to_string();
    let state = *data.get(108).ok_or_else(short)?;
    // An uninitialized account is not a token account in any meaningful sense;
    // treating it as one would report a spurious 0-amount balance.
    if state == 0 {
        return Ok(None);
    }
    // `AccountState` is 0, 1 or 2; anything else is not one (F8).
    if state > 2 {
        return Err(format!("the token account state byte is {state}"));
    }
    Ok(Some(TokenAccountView {
        mint: pubkey_at(data, 0).ok_or_else(short)?,
        owner: pubkey_at(data, 32).ok_or_else(short)?,
        amount: u64_at(data, 64).ok_or_else(short)?,
        delegate: coption_pubkey(data, 72)?,
        state,
        delegated_amount: u64_at(data, 121).ok_or_else(short)?,
        close_authority: coption_pubkey(data, 129)?,
    }))
}

/// Why data with the layout of a token account or a mint does not decode as
/// one, or `None` when it decodes or is not such a layout (F8). An account
/// whose fields cannot be read is not an account with no delegate, no close
/// authority and no mint authority — it is one Graphite cannot reason about.
fn token_layout_error(data: &[u8]) -> Option<String> {
    decode_token_account_checked(data)
        .err()
        .or_else(|| decode_mint_checked(data).err())
}

// -- Token-2022 extensions: detected and classified, not modelled -----------

/// What an extension can do to the meaning of a transfer.
///
/// Graphite decodes the BASE token layout — mint, owner, amount, delegate,
/// state, close authority — which Token and Token-2022 share. Token-2022 is an
/// extension system, and an extension can change what a transfer does without
/// changing any of those fields. Reading the bytes is not understanding the
/// behaviour, and the gap between the two is exactly the kind of thing this
/// codebase exists to refuse to paper over.
///
/// So extensions are DETECTED and CLASSIFIED rather than modelled. Nothing here
/// claims to know what a transfer hook will do; it claims that one is attached,
/// which is a fact, and that Graphite cannot say what it does, which is also a
/// fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtensionImpact {
    /// Can change where value goes, how much arrives, or whether the transfer
    /// is permitted — while the base fields look ordinary.
    AltersTransferSemantics,
    /// Can change who controls the account or mint.
    AltersAuthority,
    /// Carries data or restrictions that do not by themselves redirect value.
    Informational,
    /// A discriminant this build does not recognise. Treated as unmodelled,
    /// because an extension nobody here has heard of is not evidence of safety.
    Unknown,
}

/// One extension found on an account, by its TLV discriminant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedExtension {
    pub discriminant: u16,
    pub name: String,
    pub impact: ExtensionImpact,
}

/// Where the Token-2022 extension TLV region begins: after the base account
/// layout and the one-byte account type. Mints are padded to the same length
/// precisely so the two cannot be confused.
const T22_TLV_START: usize = TOKEN_ACCOUNT_LEN + 1;

/// The `ExtensionType` discriminants from spl-token-2022.
///
/// A discriminant that is not listed is reported by NUMBER and classified
/// `Unknown` rather than ignored — the set grows, and a build that silently
/// skipped what it did not recognise would get quieter as Token-2022 got richer.
fn extension_name(discriminant: u16) -> Option<(&'static str, ExtensionImpact)> {
    use ExtensionImpact::*;
    Some(match discriminant {
        1 => ("TransferFeeConfig", AltersTransferSemantics),
        2 => ("TransferFeeAmount", AltersTransferSemantics),
        3 => ("MintCloseAuthority", AltersAuthority),
        4 => ("ConfidentialTransferMint", AltersTransferSemantics),
        5 => ("ConfidentialTransferAccount", AltersTransferSemantics),
        6 => ("DefaultAccountState", AltersTransferSemantics),
        7 => ("ImmutableOwner", Informational),
        8 => ("MemoTransfer", Informational),
        9 => ("NonTransferable", AltersTransferSemantics),
        10 => ("InterestBearingConfig", Informational),
        11 => ("CpiGuard", Informational),
        12 => ("PermanentDelegate", AltersAuthority),
        13 => ("NonTransferableAccount", AltersTransferSemantics),
        14 => ("TransferHook", AltersTransferSemantics),
        15 => ("TransferHookAccount", AltersTransferSemantics),
        16 => ("ConfidentialTransferFeeConfig", AltersTransferSemantics),
        17 => ("ConfidentialTransferFeeAmount", AltersTransferSemantics),
        18 => ("MetadataPointer", Informational),
        19 => ("TokenMetadata", Informational),
        20 => ("GroupPointer", Informational),
        21 => ("TokenGroup", Informational),
        22 => ("GroupMemberPointer", Informational),
        23 => ("TokenGroupMember", Informational),
        // Round 21, from `spl_token_2022_interface::extension::ExtensionType`
        // (upstream `main`, read 2026-09-27). A confidential mint/burn
        // configuration is judged with the other confidential extensions:
        // inert only when unchanged and untouched by a confidential
        // instruction. A pausable mint and its accounts, a UI scale factor
        // and a burn permission redirect nothing and change no amount a
        // transfer moves — a pause makes the transfer FAIL, which the
        // simulation shows — so they are disclosed like a freeze authority.
        24 => ("ConfidentialMintBurn", AltersTransferSemantics),
        25 => ("ScaledUiAmount", Informational),
        26 => ("Pausable", Informational),
        27 => ("PausableAccount", Informational),
        28 => ("PermissionedBurn", Informational),
        _ => return None,
    })
}

/// The outcome of reading an account's extension region.
///
/// Three answers, and the difference between the last two is the whole point:
/// "no extensions were found" is a statement about the account; "the region
/// could not be read" is a statement about Graphite. An earlier version
/// collapsed both into an empty list, so a Token-2022 account whose first TLV
/// entry had a corrupt length looked exactly like an account with no
/// extensions at all — and a transfer hook behind a bad length byte would have
/// produced no finding (Round 7, R7-01).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ExtensionScan {
    /// Every extension that was read cleanly, in order.
    pub found: Vec<DetectedExtension>,
    /// Why the walk stopped early, when it did. `Some` means the list above is
    /// incomplete and the account cannot be reasoned about.
    pub malformed: Option<String>,
}

impl ExtensionScan {
    /// True only when the region was read to its end and nothing was found.
    /// The distinction from "could not read" is what this type exists for.
    pub fn is_clean(&self) -> bool {
        self.found.is_empty() && self.malformed.is_none()
    }
}

/// Every Token-2022 extension attached to this account, or why they could not
/// be read.
///
/// `is_clean()` for classic SPL Token accounts, for Token-2022 accounts with no
/// extensions, and for data too short to carry a TLV region — none of which is
/// a claim that the account is simple, only that no extension was found.
///
/// Walks the TLV with bounds checks and STOPS at the first malformed entry,
/// recording why. Stopping rather than guessing matters: a length that runs
/// past the buffer means the rest of the region cannot be read, and inventing
/// entries from whatever follows would be worse than reporting what was read.
/// Recording why matters more: without it, a stopped walk is an empty list.
pub fn detect_token2022_extensions(data: &[u8]) -> ExtensionScan {
    let mut scan = ExtensionScan::default();
    if data.len() <= T22_TLV_START {
        return scan;
    }
    // Only an account or a mint carries extensions. Any other type byte on
    // data long enough to have one is a layout this function does not
    // understand, and it says so rather than reading nothing.
    match data.get(T22_TYPE_OFFSET) {
        Some(&T22_TYPE_ACCOUNT) | Some(&T22_TYPE_MINT) => {}
        Some(other) => {
            scan.malformed = Some(format!(
                "account type byte {other} is neither Account nor Mint, so the extension region cannot be interpreted"
            ));
            return scan;
        }
        None => return scan,
    }
    let mut offset = T22_TLV_START;
    while offset < data.len() {
        if offset + 4 > data.len() {
            if short_tlv_tail_ends_region(&data[offset..]) {
                break;
            }
            scan.malformed = Some(format!(
                "{} trailing byte(s) at offset {offset} are too short to be a TLV header and are not the zero padding Token-2022 leaves",
                data.len() - offset
            ));
            return scan;
        }
        let discriminant = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let length = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;
        // Discriminant 0 is Uninitialized: the end of the meaningful region.
        if discriminant == 0 {
            break;
        }
        if offset + 4 + length > data.len() {
            scan.malformed = Some(format!(
                "extension type {discriminant} at offset {offset} declares {length} bytes but only {} remain",
                data.len() - offset - 4
            ));
            return scan;
        }
        let (name, impact) = match extension_name(discriminant) {
            Some((n, i)) => (n.to_string(), i),
            None => (
                format!("extension type {discriminant} (not named by this build)"),
                ExtensionImpact::Unknown,
            ),
        };
        scan.found.push(DetectedExtension {
            discriminant,
            name,
            impact,
        });
        offset += 4 + length;
    }
    scan
}

/// Whether `tail` — fewer than the four bytes of a TLV header, left at the
/// end of a Token-2022 extension region — ends the region cleanly.
///
/// Round 29 (audit 2026-10-20, M11/F1): it used to be malformed whatever it
/// held, and that blocked real accounts. Token-2022 never sizes an extended
/// account at exactly `Multisig::LEN` (355): `adjust_len_for_multisig` adds
/// two zero bytes, so a mint or account whose extensions total 189 bytes is
/// 357 bytes long and ends in two zeros — and Graphite answered every such
/// account with a Critical "region unreadable". The program's own walk
/// (`get_extension_types`) ends at a tail too short for a type, and at a
/// type of 0 (`Uninitialized`) however short the rest; it refuses a non-zero
/// type with no room for its length.
///
/// Accepted here: a tail whose first two bytes are a zero type, or a tail of
/// zeros. Refused: a non-zero type cut short, and a single non-zero byte —
/// which the program tolerates (its comment allows a realloc to leave one)
/// but which no size Token-2022 computes produces, so it stays the
/// fail-closed answer.
fn short_tlv_tail_ends_region(tail: &[u8]) -> bool {
    tail.iter().all(|b| *b == 0) || (tail.len() >= 2 && tail[0] == 0 && tail[1] == 0)
}

/// Decode the 82-byte SPL mint layout. Returns `None` when the data is not a
/// mint, or has the layout of one and does not decode.
pub fn decode_mint(data: &[u8]) -> Option<MintView> {
    decode_mint_checked(data).ok().flatten()
}

/// `Ok(None)`: not a mint. `Err`: the layout says mint and a field does not
/// decode (F8).
fn decode_mint_checked(data: &[u8]) -> Result<Option<MintView>, String> {
    if data.len() < MINT_LEN || data.len() == MULTISIG_LEN {
        return Ok(None);
    }
    // Exactly-82 is a classic mint. Longer data must carry the Token-2022 type
    // byte saying "mint" — otherwise a 165-byte token account would decode as
    // a mint too, and its owner field would be misread as a supply.
    if data.len() != MINT_LEN && data.get(T22_TYPE_OFFSET) != Some(&T22_TYPE_MINT) {
        return Ok(None);
    }
    let short = || "the mint layout is cut short".to_string();
    // `is_initialized` is a bool: 0 or 1 (F8).
    match *data.get(45).ok_or_else(short)? {
        0 => return Ok(None),
        1 => {}
        other => return Err(format!("the mint's is_initialized byte is {other}")),
    }
    Ok(Some(MintView {
        mint_authority: coption_pubkey(data, 0)?,
        supply: u64_at(data, 36).ok_or_else(short)?,
        decimals: *data.get(44).ok_or_else(short)?,
        freeze_authority: coption_pubkey(data, 46)?,
    }))
}

/// What changed for one account between pre-state and post-state.
///
/// `None` on either side means the account did not exist at that point:
/// `before: None` is a creation, `after: None` is a full close.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AccountDelta {
    pub pubkey: String,
    #[serde(default)]
    pub before: Option<AccountSnapshot>,
    #[serde(default)]
    pub after: Option<AccountSnapshot>,
}

impl AccountDelta {
    pub fn lamports_before(&self) -> u64 {
        self.before.as_ref().map(|s| s.lamports).unwrap_or(0)
    }
    pub fn lamports_after(&self) -> u64 {
        self.after.as_ref().map(|s| s.lamports).unwrap_or(0)
    }
    /// Signed lamport movement. i128 because a u64 difference does not fit i64
    /// at the extremes and this must never wrap.
    pub fn lamport_delta(&self) -> i128 {
        i128::from(self.lamports_after()) - i128::from(self.lamports_before())
    }
    /// True when the account held lamports before and holds none after — the
    /// on-chain definition of a closed account.
    pub fn was_closed(&self) -> bool {
        self.lamports_before() > 0 && self.lamports_after() == 0
    }
    /// True when the account did not exist (or held nothing) before and does
    /// now.
    pub fn was_created(&self) -> bool {
        self.lamports_before() == 0 && self.lamports_after() > 0
    }
    /// The owning program before and after, when both are known and differ.
    pub fn owner_change(&self) -> Option<(String, String)> {
        let (b, a) = (self.before.as_ref()?, self.after.as_ref()?);
        if b.owner == a.owner {
            None
        } else {
            Some((b.owner.clone(), a.owner.clone()))
        }
    }
    /// Signed SPL token balance movement, when both sides decode as token
    /// accounts.
    pub fn token_delta(&self) -> Option<i128> {
        let b = self.before.as_ref()?.token.as_ref()?;
        let a = self.after.as_ref()?.token.as_ref()?;
        Some(i128::from(a.amount) - i128::from(b.amount))
    }
    /// The SPL token amount this account gave up, when it was a token
    /// account before the transaction.
    ///
    /// Round 29 (audit 2026-10-20, F2): `token_delta` needs a token view on
    /// BOTH sides, so a balance moved out and the account closed in the same
    /// transaction — or wiped, or reinitialised for another mint — had no
    /// delta and was no debit: draining a token account and then closing it
    /// produced a smaller finding than draining it alone. An account that
    /// ends the transaction as no token account of the same mint has given
    /// up its whole pre-state balance.
    pub fn token_debit(&self) -> Option<u64> {
        let b = self.before.as_ref()?.token.as_ref()?;
        Some(match self.after.as_ref().and_then(|s| s.token.as_ref()) {
            Some(a) if a.mint == b.mint => b.amount.saturating_sub(a.amount),
            _ => b.amount,
        })
    }
    /// Signed mint supply movement, when both sides decode as mints.
    pub fn supply_delta(&self) -> Option<i128> {
        let b = self.before.as_ref()?.mint.as_ref()?;
        let a = self.after.as_ref()?.mint.as_ref()?;
        Some(i128::from(a.supply) - i128::from(b.supply))
    }
    /// A delegate power that exists after the transaction and did not before:
    /// a new delegate, or the same delegate allowed to move MORE (A2-02,
    /// 2026-09-29 audit). A delegation is the pair (delegate, allowance); an
    /// allowance raised from 1 to u64::MAX for an existing delegate is a grant
    /// of everything, and comparing the key alone did not see it. A lowered
    /// allowance takes power away and is not a grant.
    pub fn delegate_granted(&self) -> Option<String> {
        let after = self.after.as_ref()?.token.as_ref()?;
        let delegate = after.delegate.clone()?;
        let before = self.before.as_ref().and_then(|s| s.token.as_ref());
        match before {
            Some(b) if b.delegate.as_deref() == Some(delegate.as_str()) => {
                if after.delegated_amount > b.delegated_amount {
                    Some(format!(
                        "{delegate} (allowance raised from {} to {})",
                        b.delegated_amount, after.delegated_amount
                    ))
                } else {
                    None
                }
            }
            _ => Some(delegate),
        }
    }
    /// A close authority that exists after the transaction and did not before.
    pub fn close_authority_granted(&self) -> Option<String> {
        let after = self
            .after
            .as_ref()?
            .token
            .as_ref()?
            .close_authority
            .clone()?;
        let before = self
            .before
            .as_ref()
            .and_then(|s| s.token.as_ref())
            .and_then(|t| t.close_authority.clone());
        if before.as_deref() == Some(after.as_str()) {
            None
        } else {
            Some(after)
        }
    }
    /// True when the account went from not-frozen to frozen.
    pub fn was_frozen(&self) -> bool {
        let after_frozen = self
            .after
            .as_ref()
            .and_then(|s| s.token.as_ref())
            .map(|t| t.is_frozen())
            .unwrap_or(false);
        let before_frozen = self
            .before
            .as_ref()
            .and_then(|s| s.token.as_ref())
            .map(|t| t.is_frozen())
            .unwrap_or(false);
        after_frozen && !before_frozen
    }
    /// The token account's AUTHORITY before and after, when both sides decode
    /// as initialized token accounts and it changed.
    ///
    /// This is the SPL `owner` field — who may move the balance — and it is
    /// not the account's owning program, which `owner_change` reports. Two
    /// different facts share a word, and only one of them was being watched:
    /// `SetAuthority(AccountOwner)` leaves the owning program (the Token
    /// program) exactly where it was, so an account could change hands under a
    /// diff that reported nothing at all (GFX-002, 2026-09-17 forensic audit).
    ///
    /// Both sides must decode, which means both must be initialized —
    /// `decode_token_account` refuses state 0 — so initializing a
    /// pre-allocated account is not reported here. It is a creation, and the
    /// creation checks own it.
    pub fn token_authority_change(&self) -> Option<(String, String)> {
        let b = self.before.as_ref()?.token.as_ref()?;
        let a = self.after.as_ref()?.token.as_ref()?;
        if b.owner == a.owner {
            None
        } else {
            Some((b.owner.clone(), a.owner.clone()))
        }
    }
    /// The mint authority before and after, when both sides decode as mints
    /// and it changed.
    ///
    /// Compared as `Option`s rather than as keys, because absence is a value
    /// here: a mint whose authority was revoked and a mint that just acquired
    /// one are both changes, and requiring a key on both sides would report
    /// neither.
    pub fn mint_authority_change(&self) -> Option<(Option<String>, Option<String>)> {
        let b = self.before.as_ref()?.mint.as_ref()?;
        let a = self.after.as_ref()?.mint.as_ref()?;
        if b.mint_authority == a.mint_authority {
            None
        } else {
            Some((b.mint_authority.clone(), a.mint_authority.clone()))
        }
    }
    /// The freeze authority before and after, when both sides decode as mints
    /// and it changed. Same `Option` comparison, for the same reason.
    pub fn freeze_authority_change(&self) -> Option<(Option<String>, Option<String>)> {
        let b = self.before.as_ref()?.mint.as_ref()?;
        let a = self.after.as_ref()?.mint.as_ref()?;
        if b.freeze_authority == a.freeze_authority {
            None
        } else {
            Some((b.freeze_authority.clone(), a.freeze_authority.clone()))
        }
    }
    /// True when nothing this module can observe actually changed.
    pub fn is_noop(&self) -> bool {
        self.before == self.after
    }
}

/// The largest lamport figure this analysis will accept as a real Solana
/// transaction fee.
///
/// `fee_lamports` is CREDIT. It is subtracted from what the conservation
/// identity expects the deltas to sum to, and it exempts the fee payer's
/// outflow from the unexplained-outflow check. Nothing Graphite measures bounds
/// it: on the RPC path the number arrives in the same response as the balances
/// it is reconciling, and on the caller path it is simply asserted. An
/// unbounded fee therefore lets whoever supplies the diff balance any
/// discrepancy and excuse any drain by calling it a fee — which defeats the
/// check whose stated purpose is detecting a diff that is "incomplete or
/// fabricated". Found 2026-09-08 while attacking the RPC trust boundary.
///
/// 0.1 SOL sits far above any real fee. The base fee is 5,000 lamports per
/// signature — at most ~95,000 for a transaction packed with signatures — and a
/// priority fee is the compute-unit limit, itself capped at 1,400,000, times
/// the price in micro-lamports per CU, so even an extreme bid of 1 lamport/CU
/// comes to 1,400,000 lamports. This ceiling is ~70x that.
///
/// TRADEOFF (P14): a transaction genuinely paying more than 0.1 SOL in fees is
/// blocked here rather than analyzed. That is the fail-closed direction, and a
/// fee that size deserves a human's attention on its own merits.
pub const MAX_PLAUSIBLE_FEE_LAMPORTS: u64 = 100_000_000;

/// The rent-exempt minimum balance of an account holding `data_len` bytes,
/// under the cluster's rent parameters (`Rent::default()`: 3,480 lamports per
/// byte-year, a 2-year exemption threshold, 128 bytes of per-account
/// overhead) — 890,880 lamports for an empty account, 2,039,280 for a token
/// account (F7). It bounds what an account creation may be said to cost a
/// signer: lamports put into a new account beyond it are a transfer.
pub fn rent_exempt_minimum(data_len: usize) -> i128 {
    const LAMPORTS_PER_BYTE_YEAR: i128 = 3_480;
    const EXEMPTION_THRESHOLD_YEARS: i128 = 2;
    const ACCOUNT_STORAGE_OVERHEAD: i128 = 128;
    (ACCOUNT_STORAGE_OVERHEAD + data_len as i128)
        * LAMPORTS_PER_BYTE_YEAR
        * EXEMPTION_THRESHOLD_YEARS
}

const STAKE_PROGRAM: &str = "Stake11111111111111111111111111111111111111";
const VOTE_PROGRAM: &str = "Vote111111111111111111111111111111111111111";
/// The lockup of a stake account that locks nothing (`native_authorities`).
const NO_LOCKUP: &str = "unix 0, epoch 0";

/// The value `native_authorities` records for `what` on `snap`.
fn native_authority<'a>(snap: &'a AccountSnapshot, what: &str) -> Option<&'a str> {
    snap.native_authorities
        .iter()
        .find(|(w, _)| w == what)
        .map(|(_, who)| who.as_str())
}

/// What kind of native account `owner` makes an account, for a finding.
fn native_kind(owner: &str) -> &'static str {
    match owner {
        STAKE_PROGRAM => "stake",
        VOTE_PROGRAM => "vote",
        SYSTEM_PROGRAM => "nonce",
        _ => "native",
    }
}

/// The authorities of a native account the transaction created or
/// initialized that no signer holds (Round 34, R33-14), each as
/// "<what> <who>". Stake: the staker and the withdrawer, and the lockup
/// custodian while a lockup is in force (it alone can lift it). Vote: the
/// withdrawer, and each revenue collector unless it is the vote account
/// itself; a vote state this build cannot decode is a stranger. Nonce: its
/// authority. A stake account carrying exactly the authorities of one this
/// transaction splits from (`split_sources`) introduces no one.
fn created_authorities_not_signing(
    after: &AccountSnapshot,
    account: &str,
    signers: &std::collections::HashSet<&str>,
    split_sources: &[Vec<(String, String)>],
) -> Vec<String> {
    let signs = |who: &str| signers.contains(who);
    let mut out = Vec::new();
    match after.owner.as_str() {
        STAKE_PROGRAM => {
            if split_sources.contains(&after.native_authorities) {
                return out;
            }
            let lockup_in_force = native_authority(after, "stake lockup") != Some(NO_LOCKUP);
            for (what, who) in &after.native_authorities {
                let judged = match what.as_str() {
                    "stake staker" | "stake withdrawer" => true,
                    "stake lockup custodian" => lockup_in_force,
                    _ => false,
                };
                if judged && !signs(who) {
                    out.push(format!("{what} {who}"));
                }
            }
        }
        VOTE_PROGRAM => {
            for (what, who) in &after.native_authorities {
                let ok = match what.as_str() {
                    "vote authorized withdrawer" => signs(who),
                    "vote inflation rewards collector" | "vote block revenue collector" => {
                        signs(who) || who == account
                    }
                    // A vote state this build cannot decode.
                    _ => false,
                };
                if !ok {
                    out.push(format!("{what} {who}"));
                }
            }
        }
        SYSTEM_PROGRAM => {
            for (what, who) in &after.native_authorities {
                if what == "nonce authority" && !signs(who) {
                    out.push(format!("{what} {who}"));
                }
            }
        }
        _ => {}
    }
    out
}

/// The signer that keeps the lamports `snap` holds, when one does (Round 34,
/// R33-6/-7/-10): a token account (SPL Token or Token-2022) a signer owns,
/// not frozen, whose delegate and close authority, if any, also sign; a
/// stake account whose staker and withdrawer sign, with no lockup a
/// non-signer controls; a nonce account whose authority signs. Lamports in
/// any other account are not a signer's, whoever paid them in.
///
/// Round 39 (R39-CORE-DECISION-1): `intent_binding`'s sibling rule asks the
/// same question of the accounts value is moved to, so the two cannot drift.
pub(crate) fn lamports_kept_by(
    snap: &AccountSnapshot,
    signers: &std::collections::HashSet<&str>,
) -> Option<String> {
    let signs = |who: &str| signers.contains(who);
    if snap.owner == SPL_TOKEN_PROGRAM || snap.owner == SPL_TOKEN_2022_PROGRAM {
        let t = snap.token.as_ref()?;
        let holds = signs(&t.owner)
            && !t.is_frozen()
            && t.delegate.as_deref().is_none_or(signs)
            && t.close_authority.as_deref().is_none_or(signs);
        return holds.then(|| t.owner.clone());
    }
    match snap.owner.as_str() {
        STAKE_PROGRAM => {
            let withdrawer = native_authority(snap, "stake withdrawer")?;
            let staker = native_authority(snap, "stake staker")?;
            let lockup_free = native_authority(snap, "stake lockup") == Some(NO_LOCKUP)
                || native_authority(snap, "stake lockup custodian").is_some_and(signs);
            (signs(withdrawer) && signs(staker) && lockup_free).then(|| withdrawer.to_string())
        }
        SYSTEM_PROGRAM => native_authority(snap, "nonce authority")
            .filter(|a| signs(a))
            .map(str::to_string),
        _ => None,
    }
}

/// What each signer lost of its own, in lamports (Round 34: R33-6, R33-7,
/// R33-10). Positive is a loss nothing explains; zero or negative is none.
///
/// Until Round 34 L4 summed the signers' balance changes and subtracted
/// every lamport that arrived in a token account a signer holds and the
/// rent of every account the transaction created. Three ways that excused
/// a drain, each reproduced by the Round 33 audit:
///
/// - **R33-7**: a co-signer's gain offset the user's loss. The user's 5 SOL
///   sent to a fresh co-signing keypair, or to the relayer that pays the
///   fee, netted to nothing. Now each signer's loss is its own; another
///   signer's gain never reduces it, and lamports a signer keeps count
///   toward THAT signer only.
/// - **R33-6**: rent paid into a created account was credited whoever owned
///   it — 7.30 SOL into a 1 MiB account another program owns. Lamports in an
///   account a program owns are that program's. Now the rent of a created
///   account is a signer's cost only when the declaration NAMES the account
///   as one the instruction creates (`declared_creation`) and it ends up
///   owned by the instruction's own program or a token program; lamports in
///   an account a signer keeps (`lamports_kept_by`) count toward that
///   signer. Everything else is a loss.
/// - **R33-10**: every lamport arriving in a signer's token account was
///   credited, wherever it came from: a pool's 1 SOL wSOL payout into the
///   user's account offset 1 SOL sent from the user's wallet to an attacker.
///   Now what arrives in signers' accounts is credited only beyond what left
///   accounts no signer keeps (vaults, programs, strangers), so value paid
///   IN to the user is never read as the user's own value staying put; and
///   each signer is credited at most what it lost (min(wallet out, kept in)).
///
/// A created account that is itself a signer (a fresh keypair) is a signer
/// in its own right: its gain is its own and offsets nobody's loss. Its rent
/// is a cost to the payer only as above. A signer whose account another
/// program owns after the transaction is still judged as a signer for its
/// own losses; lamports it receives are its gain, not the user's.
/// Whether a signer holds `d` (Round 38, R37-6): it is a signer that held
/// lamports before the transaction (a keypair funded and built in this
/// transaction holds nothing yet), or on either side of the transaction it
/// is a token account a signer owns, a native account whose recorded
/// authority is a signer, or a mint whose mint, freeze or extension
/// authority is a signer.
fn signer_holds(d: &AccountDelta, signers: &std::collections::HashSet<&str>) -> bool {
    let is = |who: &str| signers.contains(who);
    let some = |who: &Option<String>| who.as_deref().is_some_and(is);
    (is(&d.pubkey) && d.lamports_before() > 0)
        || [d.before.as_ref(), d.after.as_ref()]
            .into_iter()
            .flatten()
            .any(|s| {
                s.token.as_ref().is_some_and(|t| is(&t.owner))
                    || s.native_authorities.iter().any(|(_, who)| is(who))
                    || s.mint
                        .as_ref()
                        .is_some_and(|m| some(&m.mint_authority) || some(&m.freeze_authority))
                    || s.token2022_powers.as_ref().is_some_and(|p| {
                        p.extension_authorities.iter().any(|(_, who)| some(who))
                            || p.permanent_delegate.as_ref().is_some_and(some)
                            || p.close_authority.as_ref().is_some_and(some)
                    })
            })
}

/// What one signer lost: `unexplained` after what stayed its own and the
/// rent of declared creations, and `rent` — the part of that rent netted
/// against it (Round 37, R37-7).
#[derive(Debug, Clone, Copy, Default)]
struct SignerLoss {
    unexplained: i128,
    rent: i128,
}

fn signer_lamport_losses(
    changed: &[&AccountDelta],
    signers: &std::collections::HashSet<&str>,
    fee_payer: Option<&str>,
    fee: i128,
    declared_creation: &dyn Fn(&AccountDelta) -> bool,
) -> std::collections::BTreeMap<String, SignerLoss> {
    use std::collections::BTreeMap;
    let mut out: BTreeMap<String, i128> = BTreeMap::new();
    let mut kept_in: BTreeMap<String, i128> = BTreeMap::new();
    let mut left_strangers: i128 = 0;
    let mut creation_rent: i128 = 0;
    for d in changed {
        let lam = d.lamport_delta();
        let is_signer = signers.contains(d.pubkey.as_str());
        if is_signer {
            let fee_paid = if fee_payer == Some(d.pubkey.as_str()) {
                fee
            } else {
                0
            };
            *out.entry(d.pubkey.clone()).or_default() += -lam - fee_paid;
        }
        let gained_data = d.after.as_ref().is_some_and(|s| s.data_len > 0)
            && d.before.as_ref().map(|s| s.data_len).unwrap_or(0) == 0;
        let left_system = d.after.as_ref().is_some_and(|s| s.owner != SYSTEM_PROGRAM);
        if lam > 0 {
            let keeper = if is_signer {
                None
            } else {
                d.after.as_ref().and_then(|s| lamports_kept_by(s, signers))
            };
            if let Some(h) = keeper {
                *kept_in.entry(h).or_default() += lam;
            } else if d.was_created() && (gained_data || left_system) && declared_creation(d) {
                let rent = rent_exempt_minimum(d.after.as_ref().map_or(0, |s| s.data_len));
                creation_rent += lam.min(rent);
            }
        } else if lam < 0 && !is_signer {
            let kept_before = d
                .before
                .as_ref()
                .and_then(|s| lamports_kept_by(s, signers))
                .is_some();
            if !kept_before {
                left_strangers += -lam;
            }
        }
    }
    // What arrived in signers' accounts beyond what left accounts no signer
    // keeps: only that can be the signers' own lamports changing form.
    let mut kept_pool = (kept_in.values().sum::<i128>() - left_strangers).max(0);
    // The fee payer first: it is the account that pays rent.
    let mut order: Vec<String> = out.keys().cloned().collect();
    if let Some(p) = fee_payer.filter(|p| out.contains_key(*p)) {
        order.retain(|s| s != p);
        order.insert(0, p.to_string());
    }
    let mut losses = BTreeMap::new();
    for s in order {
        let mut lost = out[&s];
        let mut rent = 0;
        if lost > 0 {
            let kept = lost
                .min(kept_in.get(&s).copied().unwrap_or(0))
                .min(kept_pool);
            kept_pool -= kept;
            lost -= kept;
            rent = lost.min(creation_rent);
            creation_rent -= rent;
            lost -= rent;
        }
        losses.insert(
            s,
            SignerLoss {
                unexplained: lost,
                rent,
            },
        );
    }
    losses
}

/// A complete pre/post picture of a transaction's effect on account state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct StateDiff {
    pub deltas: Vec<AccountDelta>,
    #[serde(default)]
    pub provenance: DiffProvenance,
    /// Transaction fee in lamports, needed to check lamport conservation.
    #[serde(default)]
    pub fee_lamports: u64,
    /// True when every account the transaction could write was snapshotted.
    /// Only then is the lamport-conservation identity meaningful.
    ///
    /// This is now MEASURED rather than declared. It used to be
    /// `transaction_instructions.len() <= 1` — a caller-supplied field whose
    /// contents nothing verifies — so a caller could switch off the
    /// lamport-conservation check by declaring a second instruction that did
    /// not exist. See `artifact_balance_writes`.
    #[serde(default)]
    pub covers_all_writable: bool,
    /// How many accounts the SIMULATOR observed changing lamport balance across
    /// the whole transaction, when an artifact was simulated.
    ///
    /// This is the number that makes coverage checkable. `simulateTransaction`
    /// returns `preBalances`/`postBalances` over the transaction's entire
    /// account list, so Graphite can count how many accounts the artifact
    /// actually moved value on without parsing the transaction and without
    /// believing anything the caller said about it. If the diff covers fewer
    /// changed accounts than that, the description does not describe the
    /// artifact — whatever the caller declared.
    ///
    /// `None` when no artifact was simulated, in which case there is nothing to
    /// compare against and coverage falls back to what the caller described.
    #[serde(default)]
    pub artifact_balance_writes: Option<u32>,
    /// `(accounts the artifact references, accounts the request accounts for)`.
    ///
    /// Balance deltas are a FLOOR on what a transaction did — they see value
    /// moving and nothing else. A secondary instruction that reassigns an
    /// account's owner, grants a delegate, sets a close authority or freezes a
    /// token account moves no lamports at all.
    ///
    /// Measured on live devnet 2026-09-08: a benign transfer and the same
    /// transfer carrying a second instruction that hands an account to an
    /// attacker program BOTH report exactly two lamport-moved accounts. The
    /// hostile one references four accounts instead of three. Coverage computed
    /// from balance movement saw nothing; the account universe is a whole
    /// account larger, and cannot be hidden — an account has to be in the
    /// transaction to be touched by it.
    ///
    /// `None` when no artifact was simulated.
    ///
    /// Superseded by `artifact_accounts_undescribed` wherever the message could
    /// be read: two numbers cannot say WHICH account went unmentioned, and a
    /// request that names one address the transaction does not contain restores
    /// the count while hiding one it does. Kept for the case where the bytes
    /// did not parse and a count is genuinely all there is.
    #[serde(default)]
    pub artifact_account_universe: Option<(usize, usize)>,
    /// Accounts the transaction references that the request names nowhere, BY
    /// ADDRESS, read out of the message's own static key list.
    ///
    /// `Some(vec![])` and `None` are different answers and the distinction is
    /// the point: the first says Graphite read the message and every account in
    /// it is accounted for, the second says it could not read the message.
    /// Collapsing them would turn "could not check" into "checked and clean",
    /// which is the shape of every fail-open this codebase exists to avoid.
    ///
    /// Static keys only. Accounts arriving through a lookup table are named in
    /// the lookup-table disclosure instead, because identifying them requires
    /// fetching the tables — Graphite does that, but the answer belongs where
    /// the reader can see it depended on an extra fetch that may not have
    /// happened.
    #[serde(default)]
    pub artifact_accounts_undescribed: Option<Vec<String>>,
    /// The `TransferFeeConfig` of every Token-2022 mint whose token accounts
    /// appear in this diff and which is not itself in it (Round 20).
    ///
    /// A `TransferChecked` names the mint read-only, so the mint is never one
    /// of the writable accounts the diff covers — yet its schedule is what
    /// says what a transfer of it costs. Graphite fetches it at pre-state.
    /// A mint missing here, and not in the diff, is a mint whose fee cannot
    /// be checked, and its transfer-fee extensions stay unmodelled.
    #[serde(default)]
    pub transfer_fee_mints: std::collections::BTreeMap<String, TransferFeeConfigView>,
    /// Every Token-2022 instruction the simulator executed, in execution
    /// order, when Graphite could resolve all of them (Round 21). `None` when
    /// the simulation reported no inner instructions, one could not be
    /// resolved, or the diff did not come from a simulation.
    ///
    /// Never deserialized: a request cannot tell the fee model what ran.
    #[serde(skip)]
    pub token2022_executed: Option<Vec<ExecutedTokenInstruction>>,
    /// The epoch the simulation ran in and the latest one the transaction can
    /// land in, when the RPC reported the epoch (Round 21). Never
    /// deserialized.
    #[serde(skip)]
    pub fee_epoch: Option<FeeEpochContext>,
    /// The pre-state of every Token-2022 mint whose extension-bearing token
    /// accounts the diff covers and which is not itself in it, fetched by
    /// Graphite (Round 21) — what a transfer hook runs and who the permanent
    /// delegate is are facts about the mint. Never deserialized.
    #[serde(skip)]
    pub token2022_mints: std::collections::BTreeMap<String, AccountSnapshot>,
    /// Every account the transaction references — its static keys and the
    /// lookup-table addresses the simulator resolved — when Graphite built
    /// this diff from the transaction's bytes (Round 21). A change to an
    /// account outside this list cannot be this transaction's. Never
    /// deserialized.
    #[serde(skip)]
    pub transaction_accounts: Option<Vec<String>>,
    /// Which of those accounts the transaction makes signers and which
    /// writable — its header and the lookup tables' writable section
    /// (Round 22). What a transfer hook can be handed is bounded by these,
    /// whatever its code does. Never deserialized.
    #[serde(skip)]
    pub transaction_privileges: Option<TransactionPrivileges>,
}

/// The privileges a transaction's bytes give its accounts (Round 22). An
/// account a program is handed can be no more privileged than this: the
/// runtime refuses a CPI that escalates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransactionPrivileges {
    pub signers: std::collections::BTreeSet<String>,
    pub writable: std::collections::BTreeSet<String>,
}

/// True when the diff carries a Token-2022 transfer-fee extension anywhere,
/// or a fee schedule Graphite fetched for it — the diffs for which the epoch
/// is worth an RPC call.
pub fn diff_involves_transfer_fee(diff: &StateDiff) -> bool {
    !diff.transfer_fee_mints.is_empty()
        || diff.deltas.iter().any(|d| {
            [d.before.as_ref(), d.after.as_ref()]
                .into_iter()
                .flatten()
                .any(|s| {
                    has_extension(s, EXT_TRANSFER_FEE_AMOUNT)
                        || has_extension(s, EXT_TRANSFER_FEE_CONFIG)
                })
        })
}

impl StateDiff {
    /// Deltas where something this module can observe actually changed.
    pub fn changed(&self) -> impl Iterator<Item = &AccountDelta> {
        self.deltas.iter().filter(|d| !d.is_noop())
    }
    pub fn is_empty(&self) -> bool {
        self.changed().next().is_none()
    }
}

/// Severity of a diff finding. Critical fails the layer; Warning is reported
/// but does not on its own block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffSeverity {
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateDiffFinding {
    /// Stable machine-readable code. Callers key alerts off this, so these
    /// strings are part of the API surface (P13).
    pub code: String,
    pub severity: DiffSeverity,
    #[serde(default)]
    pub account: Option<String>,
    pub detail: String,
}

impl StateDiffFinding {
    fn critical(code: &str, account: Option<&str>, detail: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            severity: DiffSeverity::Critical,
            account: account.map(str::to_string),
            detail: detail.into(),
        }
    }
    fn warning(code: &str, account: Option<&str>, detail: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            severity: DiffSeverity::Warning,
            account: account.map(str::to_string),
            detail: detail.into(),
        }
    }
}

/// The effects a manifest's `expected_state_changes` prose promises.
///
/// Manifests describe effects in English. Rather than requiring every manifest
/// to be rewritten with a structured schema — which would strand the entire
/// existing corpus and make this layer inert until they were all migrated —
/// the prose is parsed into the effect classes that matter for diffing. The
/// vocabulary is deliberately narrow: each keyword below appears in the shipped
/// seed manifests, and a word not listed here simply contributes no promise,
/// which is the conservative direction (an unpromised effect is a finding).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeclaredEffects {
    pub debit: bool,
    pub credit: bool,
    pub close: bool,
    pub create: bool,
    pub delegate: bool,
    pub authority: bool,
    pub mint: bool,
    pub burn: bool,
    pub freeze: bool,
    /// The manifest listed no state changes at all. Nothing was promised, so
    /// nothing about value movement can be contradicted.
    pub absent: bool,
    /// The manifest listed state changes but none of the vocabulary below
    /// matched. This is NOT the same as promising nothing — the manifest is
    /// describing effects Graphite cannot interpret — so undeclared value
    /// movement is reported as a warning rather than a block. Blocking on
    /// prose we failed to parse would punish a manifest for its wording.
    pub unrecognised: bool,
    /// Where each declared effect applies (A2-01, 2026-09-29 audit): an
    /// effect stated about `accounts.<name>` excuses that account only; one
    /// stated without naming an account excuses any. The booleans above say
    /// whether an effect is declared ANYWHERE, for the transaction-level
    /// checks; the per-account checks ask `covers`.
    scopes: std::collections::BTreeMap<&'static str, EffectScope>,
    /// The manifest's security class for the instruction, when the pipeline
    /// stated it ([`security_class_line`]). `None` when no line stated it, or
    /// lines stated two different classes.
    pub security_class: Option<String>,
    /// The located instruction's program, when the pipeline stated it
    /// ([`instruction_program_line`], Round 34). The rent of an account the
    /// declaration says this instruction creates is the signer's cost only
    /// when the account ends up owned by this program or a token program —
    /// never by "any program" (R33-6).
    pub instruction_program: Option<String>,
    /// What the located instruction's own data says it moves out of an
    /// account, in lamports, where its layout states it
    /// ([`lamport_amount_line`], Round 34, R33-15): (address, lamports).
    pub lamport_amounts: Vec<(String, u64)>,
}

/// The prefix of the line the pipeline adds naming the located
/// instruction's program (Round 34). Reserved like the class line.
pub const INSTRUCTION_PROGRAM_LINE_PREFIX: &str = "graphite: the located instruction's program is ";

/// The line naming `program` as the located instruction's program.
pub fn instruction_program_line(program: &str) -> String {
    format!("{INSTRUCTION_PROGRAM_LINE_PREFIX}{program}")
}

/// The prefix of the line the pipeline adds stating what the located
/// instruction's data moves out of an account (Round 34, R33-15). Reserved
/// like the class line.
pub const LAMPORT_AMOUNT_LINE_PREFIX: &str =
    "graphite: the located instruction's data moves lamports out of ";

/// The line stating that the located instruction's data moves `lamports`
/// out of `address`.
pub fn lamport_amount_line(address: &str, lamports: u64) -> String {
    format!("{LAMPORT_AMOUNT_LINE_PREFIX}{address}: {lamports}")
}

/// What a System instruction's data says it moves out of its first account,
/// for the instructions whose layout states it: `Transfer` (u32 tag 2,
/// lamports u64) and `CreateAccount` (tag 0, lamports u64, space, owner) —
/// both debit `accounts[0]` by exactly that amount (Round 34, R33-15).
pub fn system_lamport_debit(
    program_id: &str,
    data: &[u8],
    accounts: &[String],
) -> Option<(String, u64)> {
    if program_id != SYSTEM_PROGRAM {
        return None;
    }
    let tag = u32::from_le_bytes(data.get(0..4)?.try_into().ok()?);
    let exact_len = match tag {
        2 => 12,
        0 => 52,
        _ => return None,
    };
    if data.len() != exact_len {
        return None;
    }
    let lamports = u64::from_le_bytes(data.get(4..12)?.try_into().ok()?);
    Some((accounts.first()?.clone(), lamports))
}

/// The prefix of the line the pipeline adds to an instruction's declaration
/// for L4, stating the manifest's security class for it (R30). Reserved:
/// `manifest::validate_manifest` refuses a declaration line that begins with
/// `graphite:`, so a manifest cannot state a class for itself through prose.
pub const SECURITY_CLASS_LINE_PREFIX: &str =
    "graphite: the manifest's security class for this instruction is ";

/// The line stating `class` as the instruction's security class.
pub fn security_class_line(class: &str) -> String {
    format!("{SECURITY_CLASS_LINE_PREFIX}{class:?}")
}

/// The security classes whose instructions move value as what they are for
/// (R30). Under a declaration Graphite cannot read, a signer's loss is
/// reported rather than blocked only for these — and for an instruction the
/// manifest leaves unclassed, which is a documented residual. An `inert` or
/// `authority` instruction states that it moves nothing, so a signer's loss
/// under it is unexplained whatever its prose says.
const VALUE_MOVING_CLASSES: &[&str] = &[
    "transfer", "withdraw", "drain", "stake", "close", "create", "mint", "",
];

/// Where one declared effect applies. See `DeclaredEffects::covers`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct EffectScope {
    /// Declared without naming an account: it applies to any.
    anywhere: bool,
    /// The manifest account names it was declared about.
    accounts: std::collections::BTreeSet<String>,
}

impl DeclaredEffects {
    /// True when nothing at all was promised — an empty declaration.
    pub fn is_silent(&self) -> bool {
        self.absent
    }

    /// True when the manifest describes effects Graphite could actually map to
    /// diff outcomes. Only then can an undeclared debit be a hard failure.
    pub fn is_interpretable(&self) -> bool {
        !self.absent && !self.unrecognised
    }

    /// Whether a value movement the declaration does not explain may still
    /// be the instruction's own (R30): the declaration is silent or cannot be
    /// read, and the security class the pipeline stated is one whose
    /// instructions move value. With no class stated, no.
    pub fn class_moves_value(&self) -> bool {
        self.security_class
            .as_deref()
            .is_some_and(|c| VALUE_MOVING_CLASSES.contains(&c))
    }

    /// Whether `effect` is declared for an account known to the manifest by
    /// any of `names` (the slot names the account holds in this instruction;
    /// empty for an account the instruction does not name). An effect
    /// declared about one named account does not excuse another: "sets
    /// accounts.account owner" is InitializeAccount3's account, not every
    /// account the transaction touches (A2-01).
    pub fn covers(&self, effect: &str, names: &[&str]) -> bool {
        self.scopes
            .get(effect)
            .is_some_and(|s| s.anywhere || names.iter().any(|n| s.accounts.contains(*n)))
    }

    /// Whether `effect` is declared about an account known by any of `names`
    /// BY NAME: a line that names no account does not count (Round 34,
    /// R33-5). The signer judgements ask this — "transfers funds between the
    /// protocol and the involved accounts" does not say a signer's wallet is
    /// one of them.
    pub fn covers_by_name(&self, effect: &str, names: &[&str]) -> bool {
        self.scopes
            .get(effect)
            .is_some_and(|s| names.iter().any(|n| s.accounts.contains(*n)))
    }

    /// Whether some line declares a debit without naming any account
    /// (Round 34, R33-5). For the signer judgements such a line is a
    /// declaration Graphite cannot read: it says value moves and not whose.
    /// Measured on the shipped manifests: 1,700 of 3,518 instructions carry
    /// one (1,767 of 3,541 before Round 40's IDL rewrites and removals, 1,802
    /// before Round 36's), none beside a named debit
    /// (`tests/r30_declared_effects_census.rs`).
    pub fn debit_names_no_account(&self) -> bool {
        self.scopes.get("debit").is_some_and(|s| s.anywhere)
    }

    /// Parse the manifest's prose (A2-01, 2026-09-29 audit: rebuilt).
    ///
    /// Three rules the substring match it replaces did not have:
    ///
    /// - A list of account NAMES is not a statement of effects. The generated
    ///   `modifies writable accounts: pool, owner, lpMint, payer` line — on
    ///   2,589 of 3,195 shipped instructions — made `owner` an authority
    ///   change, `lpMint` a mint and `payer` a debit, switching the matching
    ///   L4 checks off for every account in the transaction: 417 instructions
    ///   declared an authority change, 232 a mint and 133 a debit through a
    ///   name alone. Such a line, and a bare identifier, now declares
    ///   nothing. `accounts.<x>` and `data.<x>` references are read as
    ///   references, never as words.
    /// - Words, not substrings: `payer` is not `pay`, `fees` is `fee`.
    /// - Scope: an effect stated about `accounts.<name>` applies to that
    ///   account only (`covers`).
    ///
    /// W19 (external review, verified 2026-10-03) added two more:
    ///
    /// - Role. An account named after "to"/"into" is where something ARRIVES:
    ///   it is credited, and nothing else on the line is said about it.
    ///   CloseAccount's "closes accounts.account, sends its lamports to
    ///   accounts.destination" excused a closure of the destination (usually
    ///   the user's wallet), and InitializeAccount's "sets the owner to
    ///   accounts.owner" an authority change on whatever sat in the owner
    ///   slot. An account after "from" is where something LEAVES: it is the
    ///   debit's, not the credit's.
    /// - Polarity. A line that revokes declares no grant: Revoke's "revokes
    ///   accounts.source delegated_amount" declared a delegation on source,
    ///   and so excused a delegate granted there.
    pub fn parse(expected_state_changes: &[String]) -> Self {
        // The pipeline's class line is not prose: it states nothing about
        // effects, so it neither makes a declaration non-silent nor counts as
        // a line Graphite could not read. Nor are its program and amount
        // lines (Round 34).
        let (pipeline_lines, prose): (Vec<&String>, Vec<&String>) =
            expected_state_changes.iter().partition(|l| {
                l.starts_with(SECURITY_CLASS_LINE_PREFIX)
                    || l.starts_with(INSTRUCTION_PROGRAM_LINE_PREFIX)
                    || l.starts_with(LAMPORT_AMOUNT_LINE_PREFIX)
            });
        let class_lines: Vec<&String> = pipeline_lines
            .iter()
            .copied()
            .filter(|l| l.starts_with(SECURITY_CLASS_LINE_PREFIX))
            .collect();
        let mut programs = pipeline_lines
            .iter()
            .filter_map(|l| l.strip_prefix(INSTRUCTION_PROGRAM_LINE_PREFIX))
            .map(|p| p.trim().to_string());
        let first_program = programs.next();
        let instruction_program = match first_program {
            Some(p) if programs.all(|o| o == p) => Some(p),
            _ => None,
        };
        let lamport_amounts: Vec<(String, u64)> = pipeline_lines
            .iter()
            .filter_map(|l| l.strip_prefix(LAMPORT_AMOUNT_LINE_PREFIX))
            .filter_map(|rest| {
                let (address, amount) = rest.split_once(": ")?;
                Some((address.trim().to_string(), amount.trim().parse().ok()?))
            })
            .collect();
        let mut classes = class_lines.iter().map(|l| {
            l[SECURITY_CLASS_LINE_PREFIX.len()..]
                .trim()
                .trim_matches('"')
                .to_string()
        });
        let first = classes.next();
        let security_class = match first {
            Some(c) if classes.all(|o| o == c) => Some(c),
            _ => None,
        };
        let mut e = Self {
            absent: prose.is_empty(),
            security_class,
            instruction_program,
            lamport_amounts,
            ..Self::default()
        };
        let expected_state_changes = prose;
        // Whether some line was prose Graphite could not map to an effect.
        // A name list, a bare identifier and an explicit "no state changes"
        // are read — they declare nothing — so a declaration made only of
        // those is interpretable, and an undeclared token debit under it is
        // Critical (review of the 2026-09-29 audit's fix, F1: counting them
        // as unrecognised softened that debit to a warning on 27 seed
        // instructions, and on every memo).
        let mut uninterpreted_prose = false;
        for raw in expected_state_changes.iter().copied() {
            if raw == UNDESCRIBED_INSTRUCTION_EFFECTS {
                continue;
            }
            let lower = raw.to_lowercase();
            if lower.trim_start().starts_with("modifies writable accounts")
                || !lower.trim().contains(char::is_whitespace)
                || lower.contains("no state change")
            {
                continue;
            }
            let (named, words) = effect_words(raw);
            let has = |stems: &[&str]| words.iter().any(|w| stems.iter().any(|s| w.starts_with(s)));
            let is = |forms: &[&str]| words.iter().any(|w| forms.contains(&w.as_str()));
            let mut found: Vec<&'static str> = Vec::new();
            if has(&[
                "debit", "transfer", "swap", "withdraw", "deposit", "borrow", "stake", "unstake",
                "send", "sent",
            ]) || is(&[
                "pay", "pays", "paid", "payment", "payments", "repay", "repays", "repaid", "fee",
                "fees",
            ]) {
                found.extend(["debit", "credit"]);
            }
            if has(&["credit", "receiv", "reward"]) {
                found.push("credit");
            }
            if has(&["clos"]) {
                found.push("close");
            }
            // "creator" is a role, not an act of creation (F7: metaplex
            // `SignMetadata` "marks the creator as verified").
            if words
                .iter()
                .any(|w| w.starts_with("creat") && !w.starts_with("creator"))
                || has(&["initiali", "allocat"])
                || is(&["init", "open", "opens", "opened", "opening"])
                || lower.contains("new account")
            {
                found.push("create");
            }
            // A revoke takes a delegation away; it never declares one.
            if has(&["delegat", "approv"]) && !has(&["revok"]) {
                found.push("delegate");
            }
            if has(&["authorit", "assign", "owner"]) {
                found.push("authority");
            }
            if is(&["mint", "mints", "minted", "minting"]) {
                found.push("mint");
            }
            if has(&["burn"]) {
                found.push("burn");
            }
            if has(&["freez", "froze", "thaw"]) {
                found.push("freeze");
            }
            if found.is_empty() {
                uninterpreted_prose = true;
            }
            for effect in found {
                match effect {
                    "debit" => e.debit = true,
                    "credit" => e.credit = true,
                    "close" => e.close = true,
                    "create" => e.create = true,
                    "delegate" => e.delegate = true,
                    "authority" => e.authority = true,
                    "mint" => e.mint = true,
                    "burn" => e.burn = true,
                    _ => e.freeze = true,
                }
                let scope = e.scopes.entry(effect).or_default();
                if named.is_empty() {
                    scope.anywhere = true;
                } else {
                    scope.accounts.extend(
                        named
                            .iter()
                            .filter(|(_, role)| match role {
                                NamedRole::Recipient => effect == "credit",
                                NamedRole::Source => effect != "credit",
                                NamedRole::Subject => true,
                            })
                            .map(|(name, _)| name.clone()),
                    );
                }
            }
        }
        // An undescribed instruction is interpretable: it promises nothing.
        let only_undescribed = expected_state_changes
            .iter()
            .all(|s| *s == UNDESCRIBED_INSTRUCTION_EFFECTS);
        e.unrecognised = !e.absent
            && !only_undescribed
            && uninterpreted_prose
            && !(e.debit
                || e.credit
                || e.close
                || e.create
                || e.delegate
                || e.authority
                || e.mint
                || e.burn
                || e.freeze);
        e
    }
}

/// What an account named in a declaration line is to that line (W19).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NamedRole {
    /// What the line acts on.
    Subject,
    /// Named after "from": where value leaves.
    Source,
    /// Named after "to"/"into": where value arrives.
    Recipient,
}

/// The account names a declaration line references (`accounts.<name>`),
/// each with its role on the line, and its remaining words, lowercased, with
/// every `accounts.<x>`/`data.<x>` reference removed so a name is never read
/// as a verb.
fn effect_words(line: &str) -> (Vec<(String, NamedRole)>, Vec<String>) {
    let mut named = Vec::new();
    let mut words: Vec<String> = Vec::new();
    for token in line.split(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '(' | ')')) {
        let t = token.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '_');
        if let Some(name) = t.strip_prefix("accounts.") {
            let name: String = name
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                let role = match words.last().map(String::as_str) {
                    Some("to" | "into") => NamedRole::Recipient,
                    Some("from") => NamedRole::Source,
                    _ => NamedRole::Subject,
                };
                named.push((name, role));
            }
            continue;
        }
        if t.starts_with("data.") {
            continue;
        }
        for w in t.split(|c: char| !c.is_ascii_alphanumeric()) {
            if !w.is_empty() {
                words.push(w.to_ascii_lowercase());
            }
        }
    }
    (named, words)
}

/// The declared effects of an instruction the manifest does not describe
/// (Round 19, F-19-04).
///
/// A known program's unknown instruction used to be given the prose
/// "Protocol-level state changes", which `DeclaredEffects::parse` cannot
/// interpret — and an uninterpretable declaration downgrades every undeclared
/// value movement from Critical to a warning. So the one instruction Graphite
/// knew nothing about was judged MORE leniently than every instruction it
/// knew: a Token-2022 extension instruction (tag 0x19 and up is not in the
/// manifest) could debit the signer's tokens and L4 reported a warning. The
/// manifest describes nothing for this instruction, and nothing is exactly
/// what it promises: this marker parses as an interpretable declaration of no
/// effects, so a measured token debit is a finding the verdict must answer.
pub const UNDESCRIBED_INSTRUCTION_EFFECTS: &str =
    "graphite: this instruction is not described by the manifest, so it declares no effects";

/// The layer's verdict on a diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateDiffReport {
    pub findings: Vec<StateDiffFinding>,
    /// Accounts whose observable state changed.
    pub changed_accounts: usize,
    /// True when at least one finding is Critical.
    pub blocked: bool,
    /// True when the diff carried no observable change at all.
    pub empty: bool,
}

impl StateDiffReport {
    pub fn criticals(&self) -> impl Iterator<Item = &StateDiffFinding> {
        self.findings
            .iter()
            .filter(|f| f.severity == DiffSeverity::Critical)
    }
    pub fn warnings(&self) -> impl Iterator<Item = &StateDiffFinding> {
        self.findings
            .iter()
            .filter(|f| f.severity == DiffSeverity::Warning)
    }
}

/// Everything `check_state_diff` needs. Grouped into a struct because these
/// arguments travel together and their order would otherwise be easy to
/// transpose.
pub struct StateDiffCheck<'a> {
    pub diff: &'a StateDiff,
    /// The instruction's resolved accounts, used to tell a declared-writable
    /// account from one that changed without permission.
    pub resolved_accounts: &'a [ResolvedAccount],
    /// True when `is_writable` came from the real transaction's AccountMeta
    /// data rather than from the manifest's expectation. Only grounded
    /// privileges can support a Critical undeclared-write finding (P12: never
    /// block on data that was never verified).
    pub privileges_grounded: bool,
    pub expected_state_changes: &'a [String],
    /// Fee payer, whose lamport balance always falls by at least the fee. Its
    /// fee-sized outflow is not a debit worth reporting.
    pub fee_payer: Option<&'a str>,
}

/// What modelling Token-2022's transfer fee concluded (Round 20).
///
/// Until Round 20 `TransferFeeConfig` and `TransferFeeAmount` blocked every
/// transaction they appeared in, because the amount that arrives is not the
/// amount that was sent and Graphite could not say what it was. The model
/// says: for every fee-bearing token account in the diff it reads the
/// withheld amount before and after, it takes the mint's schedule (from the
/// diff, or fetched by Graphite — never from the caller), and it requires the
/// observed movement to be exactly what Token-2022 does:
///
/// - every fee withheld at a destination is the fee the schedule charges on
///   one transfer of what arrived there, under the older or the newer
///   schedule — so the verdict can state the gross amount, the fee and what
///   arrives;
/// - tokens arriving with no fee withheld are tokens the schedule does not
///   charge, or came from a supply increase;
/// - withheld fees leave an account only by being harvested into the mint,
///   exactly;
/// - the mint's value is conserved across the accounts the diff covers:
///   amounts plus withheld pools change by exactly the supply change.
///
/// Anything else — a withdrawal of withheld fees, several fee-bearing
/// transfers into one account, an account that both sent and received, a
/// schedule that could not be read — leaves the extensions unmodelled on
/// those accounts, and they block exactly as before, now with the reason.
///
/// Round 21: when Graphite holds every Token-2022 instruction the simulator
/// executed, the model replays them instead — each transfer charged its own
/// fee, each harvest and withdrawal moving exactly the withheld amount it
/// finds — starting from the pre-state, and requires the replay to end at the
/// observed post-state exactly, for every account of the mint and for the
/// mint's own pool and supply. That covers withdrawals, several transfers
/// into one account and accounts that both send and receive; an instruction
/// the replay does not know, or an account it did not observe, still blocks.
/// When the RPC reported the epoch, only the schedule of that epoch is
/// accepted, and a pending schedule is judged against the transaction's
/// lifetime rather than disclosed.
#[derive(Default)]
struct TransferFeeModel {
    /// Accounts whose transfer-fee extensions the model accounted for.
    modelled: std::collections::HashSet<String>,
    /// Why the model could not account for an account's transfer-fee
    /// extensions.
    not_modelled: std::collections::HashMap<String, String>,
    findings: Vec<StateDiffFinding>,
}

fn has_extension(snapshot: &AccountSnapshot, discriminant: u16) -> bool {
    snapshot
        .extensions
        .found
        .iter()
        .any(|e| e.discriminant == discriminant)
}

/// One side of a fee-bearing token account: (amount, withheld), or why it
/// cannot be read. An account that does not exist, or exists uninitialized,
/// holds nothing and has withheld nothing — that is how a transfer into an
/// associated token account created in the same transaction looks.
fn fee_side(snapshot: Option<&AccountSnapshot>, mint: &str) -> Result<(u64, u64), String> {
    let Some(s) = snapshot else {
        return Ok((0, 0));
    };
    if s.extensions.malformed.is_some() {
        return Err("its extension region could not be read".to_string());
    }
    let withheld = match (has_extension(s, EXT_TRANSFER_FEE_AMOUNT), s.transfer_fee_withheld) {
        (true, Some(w)) => w,
        (true, None) => {
            return Err(
                "its TransferFeeAmount entry could not be read exactly (wrong length or more than one entry)"
                    .to_string(),
            )
        }
        (false, _) => 0,
    };
    match &s.token {
        Some(t) if t.mint != mint => Err(format!(
            "it is an account of mint {} on one side of the transaction and of {mint} on the other",
            t.mint
        )),
        Some(t) => Ok((t.amount, withheld)),
        None if withheld == 0 => Ok((0, 0)),
        None => Err(
            "it carries withheld fees but does not decode as an initialized token account"
                .to_string(),
        ),
    }
}

/// `authority_declared_for(mint)`: whether the manifest declares an authority
/// change that covers that mint account, by the same scoped rule as every
/// other authority check (`DeclaredEffects::covers`).
fn model_transfer_fees(
    diff: &StateDiff,
    authority_declared_for: &dyn Fn(&str) -> bool,
) -> TransferFeeModel {
    use std::collections::BTreeMap;
    let mut model = TransferFeeModel::default();

    // Fee-bearing token accounts and fee-configured mints, grouped by mint.
    let mut accounts: BTreeMap<String, Vec<&AccountDelta>> = BTreeMap::new();
    let mut mints: BTreeMap<String, &AccountDelta> = BTreeMap::new();
    for d in &diff.deltas {
        let sides = [d.before.as_ref(), d.after.as_ref()];
        if sides
            .iter()
            .flatten()
            .any(|s| has_extension(s, EXT_TRANSFER_FEE_AMOUNT))
        {
            match sides.iter().flatten().find_map(|s| s.token.as_ref()) {
                Some(t) => accounts.entry(t.mint.clone()).or_default().push(d),
                None => {
                    model.not_modelled.insert(
                        d.pubkey.clone(),
                        "it carries TransferFeeAmount but does not decode as a token account on either side"
                            .to_string(),
                    );
                }
            }
        }
        if sides
            .iter()
            .flatten()
            .any(|s| has_extension(s, EXT_TRANSFER_FEE_CONFIG))
        {
            if sides.iter().flatten().any(|s| s.mint.is_some()) {
                mints.insert(d.pubkey.clone(), d);
            } else {
                model.not_modelled.insert(
                    d.pubkey.clone(),
                    "it carries TransferFeeConfig but does not decode as a mint on either side"
                        .to_string(),
                );
            }
        }
    }
    // A fee-configured mint in the diff whose accounts are not is its own
    // group: its config can still change.
    let mut all_mints: Vec<String> = accounts.keys().cloned().collect();
    for m in mints.keys() {
        if !accounts.contains_key(m) {
            all_mints.push(m.clone());
        }
    }

    for mint in all_mints {
        let group: Vec<&AccountDelta> = accounts.get(&mint).cloned().unwrap_or_default();
        let mint_delta = mints.get(&mint).copied();
        let members: Vec<String> = group
            .iter()
            .map(|d| d.pubkey.clone())
            .chain(mint_delta.map(|d| d.pubkey.clone()))
            .collect();
        let refuse = |model: &mut TransferFeeModel, why: String| {
            for m in &members {
                model
                    .not_modelled
                    .entry(m.clone())
                    .or_insert_with(|| why.clone());
            }
        };

        // The schedule. The mint's own pre-state governs a transfer in this
        // transaction; a mint outside the diff was fetched at pre-state by
        // Graphite. Never the caller's word.
        let (config, mint_before_withheld, mint_after_withheld, supply_delta) = match mint_delta {
            Some(md) => {
                let before = md
                    .before
                    .as_ref()
                    .and_then(|s| s.transfer_fee_config.clone());
                let after = md
                    .after
                    .as_ref()
                    .and_then(|s| s.transfer_fee_config.clone());
                let (Some(b), Some(a)) = (before, after) else {
                    refuse(
                        &mut model,
                        format!("the TransferFeeConfig of mint {mint} could not be read exactly on both sides of the transaction"),
                    );
                    continue;
                };
                // Round 29 (audit 2026-10-20, F4): scoped. This asked whether
                // an authority change was declared ANYWHERE, so "sets
                // accounts.account owner" on one account excused rewriting
                // the fee terms of every mint in the transaction — the one
                // authority check A2-01 left global.
                if b.terms() != a.terms() && !authority_declared_for(&md.pubkey) {
                    model.findings.push(StateDiffFinding::critical(
                        "Token2022TransferFeeConfigChanged",
                        Some(md.pubkey.as_str()),
                        format!(
                            "the transfer-fee terms of this mint changed (config authority {} → {}, withdraw authority {} → {}, schedules [{}; {}] → [{}; {}]); the manifest declares no authority change. Whoever holds the config authority decides what every later transfer of this token costs",
                            authority_label(&b.config_authority),
                            authority_label(&a.config_authority),
                            authority_label(&b.withdraw_withheld_authority),
                            authority_label(&a.withdraw_withheld_authority),
                            b.older.describe(),
                            b.newer.describe(),
                            a.older.describe(),
                            a.newer.describe()
                        ),
                    ));
                }
                let (bw, aw) = (b.withheld_amount, a.withheld_amount);
                (b, bw, aw, md.supply_delta().unwrap_or(0))
            }
            None => match diff.transfer_fee_mints.get(&mint) {
                Some(c) => (c.clone(), 0, 0, 0),
                None => {
                    refuse(
                        &mut model,
                        format!(
                            "the TransferFeeConfig of mint {mint} was not available, so what a transfer of it costs is unknown"
                        ),
                    );
                    continue;
                }
            },
        };

        // Both sides of every account, exactly.
        let mut sides: Vec<(&AccountDelta, i128, i128)> = Vec::new();
        let mut before_map: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        let mut after_map: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        let mut unreadable: Option<String> = None;
        for d in &group {
            match (
                fee_side(d.before.as_ref(), &mint),
                fee_side(d.after.as_ref(), &mint),
            ) {
                (Ok((ab, wb)), Ok((aa, wa))) => {
                    before_map.insert(d.pubkey.clone(), (ab, wb));
                    after_map.insert(d.pubkey.clone(), (aa, wa));
                    sides.push((
                        d,
                        i128::from(aa) - i128::from(ab),
                        i128::from(wa) - i128::from(wb),
                    ))
                }
                (Err(why), _) | (_, Err(why)) => {
                    unreadable = Some(format!("account {} cannot be modelled: {why}", d.pubkey));
                    break;
                }
            }
        }
        if let Some(why) = unreadable {
            refuse(&mut model, why);
            continue;
        }
        let mint_withheld_delta =
            i128::from(mint_after_withheld) - i128::from(mint_before_withheld);

        // Conservation of this mint's value over the accounts the diff
        // covers. A transfer moves value from one account's amount into
        // another's amount and withheld pool; a harvest moves withheld pools
        // into the mint's; only a mint or a burn changes the total.
        let total: i128 = sides.iter().map(|(_, a, w)| a + w).sum::<i128>() + mint_withheld_delta;
        if total != supply_delta {
            refuse(
                &mut model,
                format!(
                    "the value of mint {mint} across the accounts this diff covers changed by {total} while its supply changed by {supply_delta}: tokens moved to or from an account the diff does not cover, so where the fee went cannot be established"
                ),
            );
            continue;
        }

        // Round 21: replay what the simulator executed, when Graphite has it.
        if let Some(executed) = diff.token2022_executed.as_deref() {
            let mut last_err = String::new();
            let mut outcome: Option<(TransferFeeSchedule, FeeReplay)> = None;
            for schedule in fee_schedule_candidates(&config, diff.fee_epoch) {
                let replayed = replay_fee_mint(
                    &mint,
                    schedule,
                    mint_delta.is_some(),
                    mint_before_withheld,
                    &before_map,
                    executed,
                )
                .and_then(|r| {
                    replay_matches(
                        &r,
                        &after_map,
                        mint_delta.map(|_| mint_after_withheld),
                        supply_delta,
                    )
                    .map(|()| r)
                });
                match replayed {
                    Ok(r) => {
                        outcome = Some((schedule, r));
                        break;
                    }
                    Err(e) => last_err = e,
                }
            }
            let Some((schedule, replay)) = outcome else {
                refuse(
                    &mut model,
                    format!(
                        "replaying the Token-2022 instructions the simulator executed does not reproduce the observed state of mint {mint}: {last_err}"
                    ),
                );
                continue;
            };
            replay_findings(
                &config,
                diff.fee_epoch,
                schedule,
                &replay,
                mint_delta.map(|d| d.pubkey.as_str()),
                &mut model.findings,
            );
            for m in members {
                model.modelled.insert(m);
            }
            continue;
        }

        // Withheld fees leave an account only by being harvested, exactly.
        let harvested: i128 = sides
            .iter()
            .filter(|(_, _, w)| *w < 0)
            .map(|(_, _, w)| -w)
            .sum();
        if mint_withheld_delta < 0 {
            refuse(
                &mut model,
                format!("withheld fees were withdrawn from mint {mint}; withdrawals of withheld fees are not modelled"),
            );
            continue;
        }
        if harvested > 0
            && (mint_delta.is_none()
                || mint_withheld_delta != harvested
                || sides.iter().any(|(_, a, w)| *w < 0 && *a != 0))
        {
            refuse(
                &mut model,
                format!(
                    "{harvested} withheld fee(s) left token accounts of mint {mint} without arriving in the mint's withheld pool exactly — a withdrawal of withheld fees, which is not modelled"
                ),
            );
            continue;
        }
        if mint_withheld_delta > harvested {
            refuse(
                &mut model,
                format!("the withheld pool of mint {mint} grew by more than was harvested from the accounts this diff covers"),
            );
            continue;
        }
        if harvested > 0 {
            model.findings.push(StateDiffFinding::warning(
                "Token2022WithheldFeesHarvested",
                mint_delta.map(|d| d.pubkey.as_str()),
                format!("{harvested} withheld fee(s) of this mint were harvested from token accounts into the mint, exactly"),
            ));
        }

        // Every fee withheld at a destination is the schedule's fee on one
        // transfer of what arrived there.
        let mut failed: Option<String> = None;
        for (d, a, w) in &sides {
            if *w > 0 {
                if *a < 0 {
                    failed = Some(format!(
                        "account {} both sent and received tokens of mint {mint} in this transaction, so the fee on what it received cannot be separated from what it sent",
                        d.pubkey
                    ));
                    break;
                }
                let (Ok(gross), Ok(fee)) = (u64::try_from(*a + *w), u64::try_from(*w)) else {
                    failed = Some(format!(
                        "account {} moved more than a u64 can hold",
                        d.pubkey
                    ));
                    break;
                };
                // Round 21: with the epoch read, only that epoch's schedule.
                let candidates = fee_schedule_candidates(&config, diff.fee_epoch);
                let Some(schedule) = candidates
                    .iter()
                    .copied()
                    .find(|s| s.fee(gross) == Some(fee))
                else {
                    failed = Some(format!(
                        "the fee withheld in {} ({fee}) is not the fee Token-2022 charges on one transfer of the {gross} that arrived there ({}) — several fee-bearing transfers landed in one account and the executed instructions were not available to attribute them, or the diff is not what the program produces",
                        d.pubkey,
                        candidates
                            .iter()
                            .map(|s| format!(
                                "{} under [{}]",
                                s.fee(gross).map_or("none".to_string(), |f| f.to_string()),
                                s.describe()
                            ))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                    break;
                };
                model.findings.push(StateDiffFinding::warning(
                    "Token2022TransferFeeCharged",
                    Some(d.pubkey.as_str()),
                    format!(
                        "{gross} reached this account gross and Token-2022 withheld a fee of {fee} under the mint's schedule [{}], so {} arrived — the change one transfer of {gross} produces. The executed instructions were not available, so this is the diff's arithmetic, not a per-transfer attribution: an account that also sent tokens, or received several transfers the fee cap made indistinguishable, reads the same. The withheld fee belongs to whoever holds the mint's withdraw authority ({})",
                        schedule.describe(),
                        gross - fee,
                        authority_label(&config.withdraw_withheld_authority)
                    ),
                ));
                // More of the transfer withheld than delivered: the transfer
                // is mostly a payment to the mint's withdraw authority.
                if u128::from(fee) * 2 > u128::from(gross) {
                    model.findings.push(StateDiffFinding::critical(
                        "Token2022TransferFeeMajority",
                        Some(d.pubkey.as_str()),
                        format!(
                            "Token-2022 withheld {fee} of the {gross} transferred into this account — more than half — under the mint's schedule [{}]; only {} arrived. A transfer that delivers less than it withholds pays the mint's withdraw authority ({}) more than its recipient",
                            schedule.describe(),
                            gross - fee,
                            authority_label(&config.withdraw_withheld_authority)
                        ),
                    ));
                }
                pending_schedule_findings(
                    &config,
                    diff.fee_epoch,
                    schedule,
                    &d.pubkey,
                    &[gross],
                    fee,
                    &mut model.findings,
                );
            } else if *w == 0 && *a > 0 && supply_delta <= 0 {
                // Tokens arrived and nothing was withheld. That is Token-2022
                // behaviour only when the applicable schedule charges nothing
                // on that amount.
                let Ok(arrived) = u64::try_from(*a) else {
                    failed = Some(format!(
                        "account {} moved more than a u64 can hold",
                        d.pubkey
                    ));
                    break;
                };
                let free = fee_schedule_candidates(&config, diff.fee_epoch)
                    .into_iter()
                    .find(|s| s.fee(arrived) == Some(0));
                if let Some(free) = free {
                    // W19 (external review): a pending schedule applies here
                    // too. Only the withheld branch asked, so a 0 bps schedule
                    // now with 9,000 bps pending raised nothing on this path.
                    pending_schedule_findings(
                        &config,
                        diff.fee_epoch,
                        free,
                        &d.pubkey,
                        &[arrived],
                        0,
                        &mut model.findings,
                    );
                } else {
                    failed = Some(format!(
                        "{arrived} tokens of mint {mint} arrived in {} with no fee withheld, but the mint's schedules [{}; {}] charge a fee on that amount — the diff is not what a Token-2022 transfer produces",
                        d.pubkey,
                        config.older.describe(),
                        config.newer.describe()
                    ));
                    break;
                }
            }
        }
        if let Some(why) = failed {
            refuse(&mut model, why);
            continue;
        }
        for m in members {
            model.modelled.insert(m);
        }
    }
    model
}

/// The schedules a transfer in this diff may have paid: the one its epoch
/// selects when the epoch is known, either one when it is not.
fn fee_schedule_candidates(
    config: &TransferFeeConfigView,
    epoch: Option<FeeEpochContext>,
) -> Vec<TransferFeeSchedule> {
    match epoch {
        Some(c) => vec![config.applicable_at(c.simulated_epoch)],
        None if config.older == config.newer => vec![config.older],
        None => vec![config.older, config.newer],
    }
}

/// What a pending schedule means for transfers into one account that paid
/// `fee` in total under `applied`.
///
/// A pending schedule is one the transaction can pay: its landing epoch is
/// not observable and no slot count bounds it (see `FeeEpochContext`). The
/// verdict says what would arrive under it, and a pending fee that would take
/// more than half of a transfer blocks like a current one (Round 22 — Round
/// 21 stayed silent past an assumed 9,000-slot landing margin).
fn pending_schedule_findings(
    config: &TransferFeeConfigView,
    epoch: Option<FeeEpochContext>,
    applied: TransferFeeSchedule,
    account: &str,
    grosses: &[u64],
    fee: u64,
    out: &mut Vec<StateDiffFinding>,
) {
    if applied == config.newer || config.newer == config.older {
        return;
    }
    let why = match epoch {
        None => "the current epoch was not read, so Graphite cannot rule out that it lands then".to_string(),
        Some(c) if c.durable_nonce => "it uses a durable nonce and does not expire".to_string(),
        Some(c) => format!(
            "it was simulated in epoch {}, and a blockhash lives 150 blocks, not a number of slots — a skipped slot has no block, so nothing bounds the epoch it lands in",
            c.simulated_epoch
        ),
    };
    let Some(later) = grosses
        .iter()
        .try_fold(0u64, |acc, g| acc.checked_add(config.newer.fee(*g)?))
    else {
        return;
    };
    let gross: u128 = grosses.iter().map(|g| u128::from(*g)).sum();
    if later > fee {
        out.push(StateDiffFinding::warning(
            "Token2022TransferFeeRising",
            Some(account),
            format!(
                "the mint's fee schedule changes to [{}] at epoch {}: if this transaction lands in that epoch or later the fee on it is {later}, not {fee}, and {} arrives instead of {} ({why})",
                config.newer.describe(),
                config.newer.epoch,
                gross.saturating_sub(u128::from(later)),
                gross.saturating_sub(u128::from(fee))
            ),
        ));
    }
    for g in grosses {
        if let Some(pending) = config.newer.fee(*g) {
            if pending > applied.fee(*g).unwrap_or(0) && u128::from(pending) * 2 > u128::from(*g) {
                out.push(StateDiffFinding::critical(
                    "Token2022TransferFeeMajority",
                    Some(account),
                    format!(
                        "under the mint's pending schedule [{}], from epoch {}, Token-2022 would withhold {pending} of a {g} transfer into this account — more than half — and {why}; a transfer that can deliver less than it withholds pays the mint's withdraw authority ({}) more than its recipient",
                        config.newer.describe(),
                        config.newer.epoch,
                        authority_label(&config.withdraw_withheld_authority)
                    ),
                ));
            }
        }
    }
}

/// Token-2022 instruction tags the fee replay reads (Round 21), from
/// `spl_token_2022::instruction::TokenInstruction`.
const T22_IX_TRANSFER_CHECKED: u8 = 12;
const T22_IX_MINT_TO: u8 = 7;
const T22_IX_MINT_TO_CHECKED: u8 = 14;
const T22_IX_BURN: u8 = 8;
const T22_IX_BURN_CHECKED: u8 = 15;
const T22_IX_CLOSE_ACCOUNT: u8 = 9;
const T22_IX_TRANSFER_FEE: u8 = 26;
/// `TransferFeeInstruction`, the byte after tag 26.
const T22_FEE_IX_TRANSFER_CHECKED_WITH_FEE: u8 = 1;
const T22_FEE_IX_WITHDRAW_FROM_MINT: u8 = 2;
const T22_FEE_IX_WITHDRAW_FROM_ACCOUNTS: u8 = 3;
const T22_FEE_IX_HARVEST_TO_MINT: u8 = 4;
const T22_FEE_IX_SET_TRANSFER_FEE: u8 = 5;
/// Token-2022 instructions that change no token amount and no withheld
/// amount: InitializeAccount (1, 16, 18), Approve (4, 13), Revoke (5),
/// SetAuthority (6), Freeze/Thaw (10, 11), GetAccountDataSize (21),
/// InitializeImmutableOwner (22), AmountToUiAmount / UiAmountToAmount (23,
/// 24), Reallocate (29), MemoTransfer (30), CpiGuard (34),
/// WithdrawExcessLamports (38). Anything not here and not replayed below
/// makes the replay refuse.
const T22_IX_NO_TOKEN_VALUE: [u8; 17] = [
    1, 4, 5, 6, 10, 11, 13, 16, 18, 21, 22, 23, 24, 29, 30, 34, 38,
];

/// The replay of one mint's executed instructions (Round 21).
#[derive(Default)]
struct FeeReplay {
    /// (amount, withheld) per observed token account of the mint.
    balances: std::collections::BTreeMap<String, (u64, u64)>,
    mint_withheld: u64,
    supply_change: i128,
    /// (destination, gross, fee, where) for every transfer.
    transfers: Vec<(String, u64, u64, String)>,
    harvested: u64,
    /// (destination, amount, authority, from the mint or accounts, where).
    withdrawals: Vec<(String, u64, String, &'static str, String)>,
}

fn replay_adjust(
    balances: &mut std::collections::BTreeMap<String, (u64, u64)>,
    key: &str,
    amount_delta: i128,
    withheld_delta: i128,
    at: &str,
) -> Result<(), String> {
    let Some(b) = balances.get_mut(key) else {
        return Err(format!(
            "{at} moves tokens of this mint through {key}, which the diff did not observe"
        ));
    };
    let outside = || {
        format!(
            "replaying {at} takes {key} outside what a u64 balance holds — the instructions as executed cannot produce this diff"
        )
    };
    b.0 = u64::try_from(i128::from(b.0) + amount_delta).map_err(|_| outside())?;
    b.1 = u64::try_from(i128::from(b.1) + withheld_delta).map_err(|_| outside())?;
    Ok(())
}

/// Replay `executed` against one mint's pre-state under one schedule.
fn replay_fee_mint(
    mint: &str,
    schedule: TransferFeeSchedule,
    mint_observed: bool,
    mint_withheld_before: u64,
    before: &std::collections::BTreeMap<String, (u64, u64)>,
    executed: &[ExecutedTokenInstruction],
) -> Result<FeeReplay, String> {
    let mut r = FeeReplay {
        balances: before.clone(),
        mint_withheld: mint_withheld_before,
        ..Default::default()
    };
    for ix in executed {
        let touches = ix
            .accounts
            .iter()
            .any(|a| a == mint || before.contains_key(a));
        if !touches {
            continue;
        }
        let at = ix.position.as_str();
        let Some(&tag) = ix.data.first() else {
            return Err(format!("{at} is a Token-2022 instruction with no data"));
        };
        let account = |i: usize| -> Result<&str, String> {
            ix.accounts
                .get(i)
                .map(String::as_str)
                .ok_or_else(|| format!("{at} names fewer accounts than its instruction takes"))
        };
        let amount_at = |offset: usize| -> Result<u64, String> {
            u64_at(&ix.data, offset)
                .ok_or_else(|| format!("{at} carries too little data for its amount"))
        };
        let mint_at = |i: usize| -> Result<(), String> {
            let named = account(i)?;
            if named == mint {
                Ok(())
            } else {
                Err(format!(
                    "{at} names mint {named} while touching an account of mint {mint}; Token-2022 refuses that"
                ))
            }
        };
        match (tag, ix.data.get(1).copied()) {
            (T22_IX_TRANSFER_CHECKED, _)
            | (T22_IX_TRANSFER_FEE, Some(T22_FEE_IX_TRANSFER_CHECKED_WITH_FEE)) => {
                let with_fee = tag == T22_IX_TRANSFER_FEE;
                mint_at(1)?;
                let amount = amount_at(if with_fee { 2 } else { 1 })?;
                let (source, destination) = (account(0)?, account(2)?);
                if source == destination {
                    return Err(format!(
                        "{at} transfers from an account to itself, which the fee replay does not model"
                    ));
                }
                let fee = schedule.fee(amount).ok_or_else(|| {
                    format!(
                        "the schedule [{}] is not one Token-2022 can apply",
                        schedule.describe()
                    )
                })?;
                if with_fee {
                    // tag, sub-tag, amount (8), decimals (1), then the fee.
                    let stated = amount_at(11)?;
                    if stated != fee {
                        return Err(format!(
                            "{at} states a fee of {stated} where the schedule [{}] charges {fee} on {amount}",
                            schedule.describe()
                        ));
                    }
                }
                replay_adjust(&mut r.balances, source, -i128::from(amount), 0, at)?;
                replay_adjust(
                    &mut r.balances,
                    destination,
                    i128::from(amount - fee),
                    i128::from(fee),
                    at,
                )?;
                r.transfers
                    .push((destination.to_string(), amount, fee, at.to_string()));
            }
            (T22_IX_MINT_TO | T22_IX_MINT_TO_CHECKED, _) => {
                mint_at(0)?;
                let amount = amount_at(1)?;
                replay_adjust(&mut r.balances, account(1)?, i128::from(amount), 0, at)?;
                r.supply_change += i128::from(amount);
            }
            (T22_IX_BURN | T22_IX_BURN_CHECKED, _) => {
                mint_at(1)?;
                let amount = amount_at(1)?;
                replay_adjust(&mut r.balances, account(0)?, -i128::from(amount), 0, at)?;
                r.supply_change -= i128::from(amount);
            }
            (T22_IX_CLOSE_ACCOUNT, _) => {
                let closed = account(0)?;
                if closed == mint {
                    return Err(format!(
                        "{at} closes mint {mint}, which the fee replay does not model"
                    ));
                }
                if let Some(b) = r.balances.get(closed) {
                    if *b != (0, 0) {
                        return Err(format!(
                            "{at} closes {closed} while it holds {} and has {} withheld; Token-2022 refuses that",
                            b.0, b.1
                        ));
                    }
                }
            }
            (T22_IX_TRANSFER_FEE, Some(T22_FEE_IX_WITHDRAW_FROM_MINT)) => {
                mint_at(0)?;
                if !mint_observed {
                    return Err(format!(
                        "{at} withdraws the withheld fees of mint {mint}, and the mint was not observed"
                    ));
                }
                let amount = r.mint_withheld;
                let destination = account(1)?;
                replay_adjust(&mut r.balances, destination, i128::from(amount), 0, at)?;
                r.mint_withheld = 0;
                r.withdrawals.push((
                    destination.to_string(),
                    amount,
                    account(2)?.to_string(),
                    "the mint's withheld pool",
                    at.to_string(),
                ));
            }
            (T22_IX_TRANSFER_FEE, Some(T22_FEE_IX_WITHDRAW_FROM_ACCOUNTS)) => {
                mint_at(0)?;
                let count = usize::from(
                    *ix.data
                        .get(2)
                        .ok_or_else(|| format!("{at} does not say how many accounts it drains"))?,
                );
                if ix.accounts.len() < 3 + count {
                    return Err(format!(
                        "{at} names fewer accounts than the {count} it drains"
                    ));
                }
                let destination = account(1)?;
                let sources = &ix.accounts[ix.accounts.len() - count..];
                if sources.iter().any(|s| s == destination) {
                    return Err(format!(
                        "{at} withdraws into one of the accounts it drains, which the fee replay does not model"
                    ));
                }
                let mut total: u64 = 0;
                for source in sources {
                    let Some(b) = r.balances.get_mut(source) else {
                        return Err(format!(
                            "{at} drains {source}, which the diff did not observe"
                        ));
                    };
                    total = total.checked_add(b.1).ok_or_else(|| {
                        format!("{at} drains more than a u64 holds")
                    })?;
                    b.1 = 0;
                }
                replay_adjust(&mut r.balances, destination, i128::from(total), 0, at)?;
                r.withdrawals.push((
                    destination.to_string(),
                    total,
                    account(2)?.to_string(),
                    "withheld fees in token accounts",
                    at.to_string(),
                ));
            }
            (T22_IX_TRANSFER_FEE, Some(T22_FEE_IX_HARVEST_TO_MINT)) => {
                // Harvesting is permissionless and Token-2022 skips any
                // account it cannot harvest, so an account of another mint
                // is not an error — it is simply not harvested here.
                if account(0)? != mint {
                    continue;
                }
                for source in ix.accounts.iter().skip(1) {
                    if let Some(b) = r.balances.get_mut(source) {
                        if b.1 > 0 {
                            if !mint_observed {
                                return Err(format!(
                                    "{at} harvests into mint {mint}, and the mint was not observed"
                                ));
                            }
                            r.mint_withheld = r.mint_withheld.checked_add(b.1).ok_or_else(|| {
                                format!("{at} harvests more than a u64 holds")
                            })?;
                            r.harvested = r.harvested.saturating_add(b.1);
                            b.1 = 0;
                        }
                    }
                }
            }
            // The config change is judged by the terms comparison above; the
            // schedule it writes starts two epochs out.
            (T22_IX_TRANSFER_FEE, Some(T22_FEE_IX_SET_TRANSFER_FEE)) => {}
            (t, _) if T22_IX_NO_TOKEN_VALUE.contains(&t) => {}
            (t, sub) => {
                return Err(format!(
                    "{at} is Token-2022 instruction {t}{} on an account of mint {mint}, which the fee replay does not model",
                    sub.filter(|_| t == T22_IX_TRANSFER_FEE)
                        .map(|s| format!("/{s}"))
                        .unwrap_or_default()
                ))
            }
        }
    }
    Ok(r)
}

/// Replay one fee mint's executed Token-2022 instructions over token AMOUNTS
/// alone (Round 21), for checking the model against the chain's own record:
/// a transaction's `preTokenBalances` / `postTokenBalances` carry amounts,
/// not withheld fees. An instruction that moves withheld fees (a harvest or a
/// withdrawal) is refused here, because its effect on amounts depends on
/// pools that record does not show. The verification path does not use this;
/// it replays amounts and withheld fees together (`replay_fee_mint`).
pub fn replay_fee_amounts(
    mint: &str,
    schedule: TransferFeeSchedule,
    amounts_before: &std::collections::BTreeMap<String, u64>,
    executed: &[ExecutedTokenInstruction],
) -> Result<std::collections::BTreeMap<String, u64>, String> {
    let before: std::collections::BTreeMap<String, (u64, u64)> = amounts_before
        .iter()
        .map(|(k, a)| (k.clone(), (*a, 0)))
        .collect();
    if let Some(ix) = executed.iter().find(|ix| {
        ix.accounts
            .iter()
            .any(|a| a == mint || before.contains_key(a))
            && ix.data.first() == Some(&T22_IX_TRANSFER_FEE)
            && matches!(
                ix.data.get(1),
                Some(&T22_FEE_IX_WITHDRAW_FROM_MINT)
                    | Some(&T22_FEE_IX_WITHDRAW_FROM_ACCOUNTS)
                    | Some(&T22_FEE_IX_HARVEST_TO_MINT)
            )
    }) {
        return Err(format!(
            "{} moves withheld fees, which token balances do not record",
            ix.position
        ));
    }
    let r = replay_fee_mint(mint, schedule, false, 0, &before, executed)?;
    Ok(r.balances.into_iter().map(|(k, (a, _))| (k, a)).collect())
}

/// Whether a replay ends exactly where the simulator did.
fn replay_matches(
    r: &FeeReplay,
    after: &std::collections::BTreeMap<String, (u64, u64)>,
    mint_withheld_after: Option<u64>,
    supply_delta: i128,
) -> Result<(), String> {
    for (key, observed) in after {
        let predicted = r.balances.get(key).copied().unwrap_or((0, 0));
        if predicted != *observed {
            return Err(format!(
                "the replay ends {key} at {} with {} withheld, and the simulator reports {} with {} withheld",
                predicted.0, predicted.1, observed.0, observed.1
            ));
        }
    }
    match mint_withheld_after {
        Some(observed) if observed != r.mint_withheld => {
            return Err(format!(
            "the replay ends the mint's withheld pool at {}, and the simulator reports {observed}",
            r.mint_withheld
        ))
        }
        None if r.mint_withheld != 0 => {
            return Err(
                "the replay moves withheld fees into a mint the diff did not observe".to_string(),
            )
        }
        _ => {}
    }
    if r.supply_change != supply_delta {
        return Err(format!(
            "the replay changes the supply by {}, and the simulator reports {supply_delta}",
            r.supply_change
        ));
    }
    Ok(())
}

/// The verdict's account of a replay that matched.
fn replay_findings(
    config: &TransferFeeConfigView,
    epoch: Option<FeeEpochContext>,
    schedule: TransferFeeSchedule,
    r: &FeeReplay,
    mint_account: Option<&str>,
    out: &mut Vec<StateDiffFinding>,
) {
    use std::collections::BTreeMap;
    // Per destination: the gross of every transfer and the fees withheld.
    let mut arrivals: BTreeMap<&str, (Vec<u64>, u64)> = BTreeMap::new();
    for (destination, gross, fee, _) in &r.transfers {
        let e = arrivals.entry(destination.as_str()).or_default();
        e.0.push(*gross);
        // Saturating, and the gross in u128 (A2-10, 2026-09-29 audit): three
        // transfers of 2^63 between two accounts overflowed the per-
        // destination sum — a panic in a debug build, a wrapped figure in a
        // finding's text in release.
        e.1 = e.1.saturating_add(*fee);
    }
    for (destination, (grosses, fee)) in &arrivals {
        let gross: u128 = grosses.iter().map(|g| u128::from(*g)).sum();
        if *fee > 0 {
            let what = if grosses.len() == 1 {
                format!("{gross} was transferred into this account")
            } else {
                format!(
                    "{} transfers totalling {gross} were made into this account",
                    grosses.len()
                )
            };
            out.push(StateDiffFinding::warning(
                "Token2022TransferFeeCharged",
                Some(destination),
                format!(
                    "{what} and Token-2022 withheld a fee of {fee} under the mint's schedule [{}], so {} arrived; the withheld fee belongs to whoever holds the mint's withdraw authority ({})",
                    schedule.describe(),
                    gross.saturating_sub(u128::from(*fee)),
                    authority_label(&config.withdraw_withheld_authority)
                ),
            ));
        }
        pending_schedule_findings(config, epoch, schedule, destination, grosses, *fee, out);
    }
    for (destination, gross, fee, at) in &r.transfers {
        if u128::from(*fee) * 2 > u128::from(*gross) {
            out.push(StateDiffFinding::critical(
                "Token2022TransferFeeMajority",
                Some(destination.as_str()),
                format!(
                    "Token-2022 withheld {fee} of the {gross} transferred into this account by {at} — more than half — under the mint's schedule [{}]; only {} arrived. A transfer that delivers less than it withholds pays the mint's withdraw authority ({}) more than its recipient",
                    schedule.describe(),
                    gross - fee,
                    authority_label(&config.withdraw_withheld_authority)
                ),
            ));
        }
    }
    if r.harvested > 0 {
        out.push(StateDiffFinding::warning(
            "Token2022WithheldFeesHarvested",
            mint_account,
            format!(
                "{} withheld fee(s) of this mint were harvested from token accounts into the mint, exactly",
                r.harvested
            ),
        ));
    }
    for (destination, amount, authority, from, at) in &r.withdrawals {
        out.push(StateDiffFinding::warning(
            "Token2022WithheldFeesWithdrawn",
            Some(destination.as_str()),
            format!(
                "{at} withdrew {amount} from {from} into this account; Token-2022 accepted {authority} as the mint's withdraw authority (named {} before the transaction), and the withdrawn amount is exactly what was withheld",
                authority_label(&config.withdraw_withheld_authority)
            ),
        ));
    }
}

/// The pre-state of `mint`: its own delta when the diff covers it, else the
/// snapshot Graphite fetched.
fn mint_snapshot<'a>(diff: &'a StateDiff, mint: &str) -> Option<&'a AccountSnapshot> {
    diff.deltas
        .iter()
        .find(|d| d.pubkey == mint)
        .and_then(|d| d.before.as_ref().or(d.after.as_ref()))
        .or_else(|| diff.token2022_mints.get(mint))
}

/// What a mint's transfer hook could do in THIS transaction, bounded by the
/// transaction's bytes rather than by the hook's code (Round 22).
///
/// Token-2022 invokes the hook with the transfer's source, mint, destination
/// and authority read-only and unsigned (`spl_transfer_hook_interface::
/// instruction::execute`), and appends the extra accounts its validation
/// list names — which it can only take from the accounts the transfer was
/// itself handed, at no more privilege than the transaction gives them (the
/// runtime refuses a CPI that escalates). So whatever the hook program does,
/// at simulation or at landing, it can hold a signature only if one of those
/// accounts signs the transaction, and write only those the transaction marks
/// writable — and of those, move value only out of accounts it owns, or via a
/// signature or delegation over another program's account.
///
/// The hook is inert here when every executed Token-2022 instruction that can
/// invoke it for this mint hands it no signer of the transaction and no
/// writable account the hook does not own. Top-level transfers are fixed by
/// the bytes; a transfer made by CPI is taken as the simulator executed it.
/// Anything unobserved — the executed list, the privileges, an account's
/// owner — is `Err`, and the extension blocks as before.
pub fn transfer_hook_reach(diff: &StateDiff, mint: &str, hook: &str) -> Result<String, String> {
    let executed = diff.token2022_executed.as_ref().ok_or_else(|| {
        format!(
            "its mint's transfer hook runs program {hook}, and the executed instructions were not available to show what that program could be handed"
        )
    })?;
    let privileges = diff.transaction_privileges.as_ref().ok_or_else(|| {
        format!(
            "its mint's transfer hook runs program {hook}, and the transaction's own privileges were not read"
        )
    })?;
    let mut runs = 0usize;
    let mut owned: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for ix in executed
        .iter()
        .filter(|ix| ix.accounts.iter().any(|a| a == mint))
    {
        // What Token-2022 can hand the hook from this instruction. The
        // checked transfers pass [source, mint, destination, authority,
        // ...]: the four go read-only, the rest are what the extra metas
        // draw on (multisig signers included — a signer there fails the
        // rule, which is the point). A confidential transfer's layout is not
        // read here: all of its accounts count. No other instruction invokes
        // a hook.
        let reach: &[String] = match (ix.data.first(), ix.data.get(1)) {
            (Some(&T22_IX_TRANSFER_CHECKED), _) => ix.accounts.get(4..).unwrap_or(&[]),
            (Some(&T22_IX_TRANSFER_FEE), Some(&T22_FEE_IX_TRANSFER_CHECKED_WITH_FEE)) => {
                ix.accounts.get(4..).unwrap_or(&[])
            }
            (Some(t), _) if T22_CONFIDENTIAL_INSTRUCTIONS.contains(t) => &ix.accounts,
            _ => continue,
        };
        runs += 1;
        for a in reach {
            if privileges.signers.contains(a) {
                return Err(format!(
                    "its mint's transfer hook runs program {hook}, and {} hands it {a}, which signs this transaction — the hook would hold that signature",
                    ix.position
                ));
            }
            if privileges.writable.contains(a) {
                let owner = diff
                    .deltas
                    .iter()
                    .find(|d| d.pubkey == *a)
                    .and_then(|d| d.before.as_ref())
                    .map(|s| s.owner.as_str());
                match owner {
                    Some(o) if o == hook => {
                        owned.insert(a.as_str());
                    }
                    Some(o) => {
                        return Err(format!(
                            "its mint's transfer hook runs program {hook}, and {} hands it {a} writable, an account owned by {o} — the hook could move what it holds",
                            ix.position
                        ))
                    }
                    None => {
                        return Err(format!(
                            "its mint's transfer hook runs program {hook}, and {} hands it {a} writable, an account Graphite did not observe before the transaction",
                            ix.position
                        ))
                    }
                }
            }
        }
    }
    Ok(if runs == 0 {
        format!("its mint's transfer hook runs program {hook}, and no transfer of mint {mint} ran in this transaction")
    } else {
        format!(
            "its mint's transfer hook runs program {hook} under {runs} transfer(s), and the bytes hand it no signer and no writable account but {} of its own — whatever its code does, it can move nothing outside its own accounts",
            owned.len()
        )
    })
}

/// Every transfer-hook program a mint in this diff runs, with whether the
/// hook is bounded by the bytes as `transfer_hook_reach` decides it
/// (Round 22). A program named by two mints is bounded only if both are.
pub fn transfer_hooks_bounded(
    diff: &StateDiff,
) -> std::collections::BTreeMap<String, Result<String, String>> {
    let mut mints: std::collections::BTreeMap<&str, &AccountSnapshot> =
        std::collections::BTreeMap::new();
    for d in &diff.deltas {
        if let Some(s) = d.before.as_ref().or(d.after.as_ref()) {
            if s.mint.is_some() {
                mints.insert(d.pubkey.as_str(), s);
            }
        }
    }
    for (k, s) in &diff.token2022_mints {
        mints.entry(k.as_str()).or_insert(s);
    }
    let mut out: std::collections::BTreeMap<String, Result<String, String>> =
        std::collections::BTreeMap::new();
    for (mint, snap) in mints {
        let Some(Some(Some(hook))) = snap
            .token2022_powers
            .as_ref()
            .map(|p| p.transfer_hook_program.clone())
        else {
            continue;
        };
        let verdict = transfer_hook_reach(diff, mint, &hook);
        match out.get(&hook) {
            Some(Err(_)) => {}
            _ => {
                out.insert(hook, verdict);
            }
        }
    }
    out
}

/// Whether one extension on one account changes nothing about THIS
/// transaction (Round 21). `Ok` carries why it is inert, `Err` why it is not;
/// an extension this does not judge is `Err` with an empty reason.
///
/// Until Round 21 every one of these blocked on sight — so did a PYUSD
/// transfer, whose mint carries a transfer hook that names no program and a
/// confidential-transfer configuration nobody used. What an extension COULD
/// do is the issuer's standing power over the token; what this transaction
/// DOES with it is what the verdict is about.
fn extension_judgement(
    diff: &StateDiff,
    delta: &AccountDelta,
    disc: u16,
) -> Result<String, String> {
    let sides = [delta.before.as_ref(), delta.after.as_ref()];
    let powers = |s: Option<&AccountSnapshot>| s.map(|s| s.token2022_powers.clone());
    match disc {
        EXT_TRANSFER_HOOK_ACCOUNT => {
            let mint = sides
                .iter()
                .flatten()
                .find_map(|s| s.token.as_ref().map(|t| t.mint.clone()))
                .ok_or_else(|| "it does not decode as a token account".to_string())?;
            let m = mint_snapshot(diff, &mint).ok_or_else(|| {
                format!("its mint {mint} was not read, so the hook it runs is unknown")
            })?;
            match m
                .token2022_powers
                .as_ref()
                .map(|p| p.transfer_hook_program.clone())
            {
                None => Err(format!(
                    "the extensions of its mint {mint} could not be read exactly"
                )),
                Some(None) => Ok(
                    "its mint carries no transfer hook, so the flag triggers nothing".to_string(),
                ),
                Some(Some(None)) => {
                    Ok("its mint's transfer hook names no program, so no hook runs".to_string())
                }
                Some(Some(Some(p))) => transfer_hook_reach(diff, &mint, &p),
            }
        }
        EXT_TRANSFER_HOOK => {
            let (b, a) = (powers(sides[0]), powers(sides[1]));
            match (b, a) {
                (Some(Some(b)), Some(Some(a)))
                    if b.transfer_hook_program == a.transfer_hook_program =>
                {
                    match b.transfer_hook_program {
                        Some(None) => {
                            Ok("the transfer hook names no program, so no hook runs".to_string())
                        }
                        Some(Some(p)) => transfer_hook_reach(diff, &delta.pubkey, &p),
                        None => Ok("no transfer hook".to_string()),
                    }
                }
                _ => {
                    Err("the transfer hook changed, or could not be read on both sides".to_string())
                }
            }
        }
        d if CONFIDENTIAL_EXTENSIONS.contains(&d) => {
            let executed = diff.token2022_executed.as_ref().ok_or_else(|| {
                "the executed instructions were not available to show no confidential instruction ran".to_string()
            })?;
            if let Some(ix) = executed.iter().find(|ix| {
                ix.data
                    .first()
                    .is_some_and(|t| T22_CONFIDENTIAL_INSTRUCTIONS.contains(t))
                    && ix.accounts.iter().any(|a| a == &delta.pubkey)
            }) {
                return Err(format!(
                    "{} is a confidential-transfer instruction on it, and encrypted balances are not modelled",
                    ix.position
                ));
            }
            match (powers(sides[0]), powers(sides[1])) {
                (Some(Some(b)), Some(Some(a))) if b.confidential_digest == a.confidential_digest => Ok(
                    "its confidential-transfer state is byte-for-byte unchanged and no confidential instruction ran on it".to_string(),
                ),
                _ => Err("its confidential-transfer state changed, or could not be read on both sides".to_string()),
            }
        }
        EXT_PERMANENT_DELEGATE | EXT_MINT_CLOSE_AUTHORITY => {
            if diff.token2022_executed.is_none() {
                return Err(
                    "the executed instructions were not available to show it was not exercised"
                        .to_string(),
                );
            }
            match (powers(sides[0]), powers(sides[1])) {
                (Some(Some(b)), Some(Some(a)))
                    if b.permanent_delegate == a.permanent_delegate
                        && b.close_authority == a.close_authority =>
                {
                    Ok("a standing power of the issuer, unchanged by this transaction and not exercised in it (an exercise is reported as Token2022PermanentDelegateExercised)".to_string())
                }
                _ => Err("it changed in this transaction, or could not be read on both sides".to_string()),
            }
        }
        _ => Err(String::new()),
    }
}

/// Transfers and burns this transaction made under a mint's permanent
/// delegate out of accounts the delegate does not own (Round 21). The
/// delegate needs no permission from the holder; the executed instructions
/// are the only place the exercise shows.
fn permanent_delegate_exercises(diff: &StateDiff) -> Vec<StateDiffFinding> {
    let Some(executed) = diff.token2022_executed.as_ref() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for ix in executed {
        // (source index, mint index, authority index)
        let slots = match (ix.data.first(), ix.data.get(1)) {
            (Some(&T22_IX_TRANSFER_CHECKED), _) => (0, 1, 3),
            (Some(&T22_IX_TRANSFER_FEE), Some(&T22_FEE_IX_TRANSFER_CHECKED_WITH_FEE)) => (0, 1, 3),
            (Some(&T22_IX_BURN), _) | (Some(&T22_IX_BURN_CHECKED), _) => (0, 1, 2),
            _ => continue,
        };
        let (Some(source), Some(mint), Some(authority)) = (
            ix.accounts.get(slots.0),
            ix.accounts.get(slots.1),
            ix.accounts.get(slots.2),
        ) else {
            continue;
        };
        let source_before = diff
            .deltas
            .iter()
            .find(|d| &d.pubkey == source)
            .and_then(|d| d.before.as_ref())
            .and_then(|s| s.token.as_ref());
        let holders_own = source_before.is_some_and(|t| {
            &t.owner == authority || t.delegate.as_deref() == Some(authority.as_str())
        });
        let Some(mint_state) = mint_snapshot(diff, mint) else {
            // A2-03 (2026-09-29 audit): an unread mint is not a mint without
            // a permanent delegate. The movement is the holder's own — its
            // owner or its ordinary delegate signing — or it could be the
            // mint's; which, Graphite cannot say, so it is refused.
            if !holders_own {
                out.push(StateDiffFinding::critical(
                    "Token2022MintUnread",
                    Some(source.as_str()),
                    format!(
                        "{} moves tokens out of this account under authority {authority}, which is not shown to be its owner or delegate, and mint {mint} could not be read — a permanent delegate cannot be ruled out",
                        ix.position
                    ),
                ));
            }
            continue;
        };
        // W19 (external review): a mint read but whose extensions could not
        // be decoded exactly is no better known than one not read at all; it
        // was treated as having no permanent delegate.
        let Some(powers) = mint_state.token2022_powers.as_ref() else {
            if !holders_own {
                out.push(StateDiffFinding::critical(
                    "Token2022MintUnread",
                    Some(source.as_str()),
                    format!(
                        "{} moves tokens out of this account under authority {authority}, which is not shown to be its owner or delegate, and the extensions of mint {mint} could not be read exactly — a permanent delegate cannot be ruled out",
                        ix.position
                    ),
                ));
            }
            continue;
        };
        let Some(delegate) = powers.permanent_delegate.clone().flatten() else {
            continue;
        };
        if &delegate != authority {
            continue;
        }
        let owner = diff
            .deltas
            .iter()
            .find(|d| &d.pubkey == source)
            .and_then(|d| d.before.as_ref())
            .and_then(|s| s.token.as_ref())
            .map(|t| t.owner.clone());
        if owner.as_deref() == Some(delegate.as_str()) {
            continue;
        }
        out.push(StateDiffFinding::critical(
            "Token2022PermanentDelegateExercised",
            Some(source.as_str()),
            format!(
                "{} moves tokens out of this account under mint {mint}'s permanent delegate {delegate}, which {} — the holder did not authorize it",
                ix.position,
                owner.map_or("could not be shown to own the account".to_string(), |o| format!("does not own it (the owner is {o})"))
            ),
        ));
    }
    out
}

/// Compare an observed state diff against a manifest's declared effects.
///
/// This never returns a layer status — the caller maps findings and provenance
/// onto `LayerStatus`, because the provenance rule is a pipeline policy, not a
/// property of the diff (P7: a verdict is computed at the layer that owns it).
/// The operator's relaxations of L4's production defaults (Round 32,
/// P14). Off by default: each restores a warning a previous round gave,
/// where the default now refuses. The server and CLI read them from
/// strict-parsed environment variables and log each one that is on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct L4Relaxations {
    /// `GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS`: a signer's loss under
    /// a declaration Graphite cannot read is a warning when the manifest's
    /// class for the instruction moves value (the Round 30 rule). Off, the
    /// loss is Critical whatever the class.
    pub unreadable_value_declarations: bool,
    /// `GRAPHITE_ALLOW_SIGNER_LAMPORTS_OUTSIDE_DECLARED_DEBIT`: lamports
    /// leaving a signer's own wallet beyond the fee and the rent of accounts
    /// the transaction creates, under a declaration that debits only other
    /// named accounts, are a warning (W19's rule). Off, they are Critical.
    pub signer_lamports_outside_declared_debit: bool,
}

/// L4 under its production defaults: no relaxation.
pub fn check_state_diff(input: &StateDiffCheck<'_>) -> StateDiffReport {
    check_state_diff_with(input, L4Relaxations::default())
}

/// L4 under the operator's relaxations (see [`L4Relaxations`]).
pub fn check_state_diff_with(input: &StateDiffCheck<'_>, relax: L4Relaxations) -> StateDiffReport {
    let declared = DeclaredEffects::parse(input.expected_state_changes);
    let mut findings: Vec<StateDiffFinding> = Vec::new();

    let writable: std::collections::HashSet<&str> = input
        .resolved_accounts
        .iter()
        .filter(|a| a.is_writable)
        .map(|a| a.address.as_str())
        .collect();
    let known_accounts: std::collections::HashSet<&str> = input
        .resolved_accounts
        .iter()
        .map(|a| a.address.as_str())
        .collect();

    // Round 21: the accounts a change may correspond to. The instruction's
    // own, and — for a diff Graphite built from the bytes — every account the
    // transaction references: the diff covers the transaction, and another
    // instruction of it changing its own accounts is not a diff that fails to
    // correspond. Every value movement is still judged below.
    let in_transaction: std::collections::HashSet<&str> = known_accounts
        .iter()
        .copied()
        .chain(
            input
                .diff
                .transaction_accounts
                .iter()
                .flatten()
                .map(String::as_str),
        )
        .collect();

    let changed: Vec<&AccountDelta> = input.diff.changed().collect();

    // ── Diff integrity ──────────────────────────────────────────────────────
    //
    // Checked before anything is inferred FROM the diff, because a diff that
    // fails these is not evidence of anything.

    // The fee is credit, so an implausible one is not a detail — it is the
    // lever that makes both of the checks below satisfiable on demand. Clamp
    // what is granted and say so; a diff that needs an impossible fee to
    // balance is not evidence about anything.
    let claimed_fee = input.diff.fee_lamports;
    let fee_lamports = claimed_fee.min(MAX_PLAUSIBLE_FEE_LAMPORTS);
    if claimed_fee > MAX_PLAUSIBLE_FEE_LAMPORTS {
        findings.push(StateDiffFinding::critical(
            "ImplausibleFee",
            None,
            format!(
                "the diff declares a transaction fee of {claimed_fee} lamports, above the {MAX_PLAUSIBLE_FEE_LAMPORTS} a Solana fee can plausibly reach. The fee is credited against both lamport conservation and the fee payer's outflow, so an inflated one balances a fabricated diff and excuses a drain — only {MAX_PLAUSIBLE_FEE_LAMPORTS} was granted"
            ),
        ));
    }

    // ── Does this diff cover what the artifact actually did? ────────────────
    //
    // CRITICAL, found 2026-09-08 attacking the artifact boundary. Coverage was
    // `transaction_instructions.len() <= 1`, and that field is caller-declared
    // with no verification of its contents. Declaring one fictional extra
    // instruction set `covers_all_writable = false`, which skipped lamport
    // conservation, which was the only check binding the artifact's effects to
    // the described account set.
    //
    // Measured end to end against live devnet: a request describing a 0.002 SOL
    // transfer to Bob, carrying a signed artifact sending 0.9 SOL to Mallory,
    // came back `approved: true` with `scope: artifact_bound` and L4 reporting
    // "no undeclared effects". The attacker's whole contribution was a second
    // instruction that did not exist.
    //
    // The simulator's balance arrays cover the transaction's entire account
    // list, so the count of accounts it moved value on is available without
    // parsing the artifact and without trusting the caller. If the diff
    // accounts for fewer of them than the artifact changed, this verdict is
    // about a different transaction.
    // ── Does the request account for every account the artifact touches? ────
    //
    // The check below this one compares BALANCE movement, which is a floor: it
    // cannot see an owner reassignment, a delegate grant, a close-authority
    // change, a freeze, or any other state mutation that moves no value. This
    // one compares the size of the account universe instead, and an account
    // cannot be mutated without appearing in the transaction that mutates it.
    //
    // Reported rather than silently folded into the coverage flag because the
    // two say different things, and an operator investigating an alert needs to
    // know which one fired: "value moved somewhere you did not look" is a
    // different problem from "this transaction involves accounts you never
    // mentioned".
    // -- Token-2022 extensions, named where they were found ----------------
    //
    // Graphite decodes the base layout that Token and Token-2022 share. An
    // extension can change what a transfer DOES without changing any base
    // field: a fee can take a cut, a hook can run arbitrary code, a permanent
    // delegate can move the balance, a non-transferable flag can forbid the
    // whole thing. A verdict that says "the balances moved as described" while
    // one of those is attached is describing arithmetic, not behaviour.
    //
    // RECORDED TRADEOFF (P14). An extension that can alter transfer semantics
    // BLOCKS, and so does one this build does not recognise. That is
    // deliberately conservative and it has a real cost: every token account of
    // a fee-bearing mint carries `TransferFeeAmount`, so ordinary transfers of
    // those tokens are refused rather than approved-with-a-note. The
    // alternative is approving a transfer whose arriving amount Graphite cannot
    // compute, which is the thing this whole codebase exists not to do. The
    // finding names the extension so an operator can decide, and modelling a
    // given extension properly is how it stops blocking — not lowering this.
    //
    // Round 20: the transfer-fee pair is the first extension modelled that
    // way. On an account the model accounted for exactly, TransferFeeConfig
    // and TransferFeeAmount no longer block and the fee is disclosed; on any
    // other account they block as before, with the model's reason.
    // The manifest slot names each account holds in this instruction, for
    // the scoped per-account checks (A2-01): an effect the manifest states
    // about `accounts.<name>` excuses that account and no other.
    let mut names_of: std::collections::HashMap<&str, Vec<&str>> = std::collections::HashMap::new();
    for a in input.resolved_accounts {
        if !a.name.is_empty() {
            names_of
                .entry(a.address.as_str())
                .or_default()
                .push(a.name.as_str());
        }
    }
    let declares_for = |account: &str, effect: &str| {
        declared.covers(
            effect,
            names_of.get(account).map(Vec::as_slice).unwrap_or(&[]),
        )
    };
    let fee_model = model_transfer_fees(input.diff, &|mint: &str| declares_for(mint, "authority"));
    findings.extend(fee_model.findings.iter().cloned());
    findings.extend(permanent_delegate_exercises(input.diff));
    let is_fee_extension = |e: &DetectedExtension| {
        matches!(
            e.discriminant,
            EXT_TRANSFER_FEE_CONFIG | EXT_TRANSFER_FEE_AMOUNT
        )
    };
    for delta in input.diff.deltas.iter() {
        let fee_modelled = fee_model.modelled.contains(&delta.pubkey);
        // Round 29 (audit 2026-10-20, F3): BOTH sides. Only the post-state was
        // scanned (the pre-state when there was none), so an account the
        // transaction closed — or stripped, or rewrote — was judged on what
        // it became: a TransferHookAccount, a permanent delegate or a
        // confidential balance on the account as it ENTERED the transaction
        // was never looked at, and neither was an unreadable pre-state region.
        let scans: Vec<&ExtensionScan> = [delta.after.as_ref(), delta.before.as_ref()]
            .into_iter()
            .flatten()
            .map(|snap| &snap.extensions)
            .collect();
        // A region that could not be read is not a region with nothing in it.
        // Checked FIRST, so a corrupt length byte in front of a transfer hook
        // cannot turn the hook into silence.
        if let Some(scan) = scans.iter().find(|s| s.malformed.is_some()) {
            let why = scan.malformed.as_deref().unwrap_or_default();
            findings.push(match why.strip_prefix(TOKEN_LAYOUT_UNDECODABLE) {
                // F8: the base layout itself, on either token program.
                Some(base) => StateDiffFinding::critical(
                    "TokenLayoutUndecodable",
                    Some(delta.pubkey.as_str()),
                    format!(
                        "this account has the layout of an SPL token account or mint, but its fields do not decode ({base}); no program-written account carries such a value, so its balance and authorities are unknown — an account Graphite cannot read is not an account it can approve"
                    ),
                ),
                None => StateDiffFinding::critical(
                    "Token2022ExtensionRegionUnreadable",
                    Some(delta.pubkey.as_str()),
                    format!(
                        "the extension region of this Token-2022 account could not be read ({why}); {} extension(s) were read before the walk stopped and whatever follows is unknown — an account Graphite cannot read is not an account it can approve",
                        scan.found.len()
                    ),
                ),
            });
            continue;
        }
        // Every extension found on either side, once per discriminant
        // present, in the order first seen (post-state first).
        let mut extensions: Vec<DetectedExtension> = Vec::new();
        for scan in &scans {
            for e in &scan.found {
                let seen_here = scan
                    .found
                    .iter()
                    .filter(|x| x.discriminant == e.discriminant)
                    .count();
                let kept = extensions
                    .iter()
                    .filter(|x| x.discriminant == e.discriminant)
                    .count();
                if kept < seen_here {
                    extensions.push(e.clone());
                }
            }
        }
        if extensions.is_empty() {
            continue;
        }
        // Round 21: extensions that change nothing about this transaction.
        let mut inert: Vec<String> = Vec::new();
        let mut not_inert: std::collections::HashMap<u16, String> =
            std::collections::HashMap::new();
        for e in &extensions {
            match extension_judgement(input.diff, delta, e.discriminant) {
                Ok(why) => inert.push(format!("{}: {why}", e.name)),
                Err(why) if !why.is_empty() => {
                    not_inert.insert(e.discriminant, why);
                }
                Err(_) => {}
            }
        }
        let is_inert =
            |e: &DetectedExtension| inert.iter().any(|w| w.starts_with(&format!("{}:", e.name)));
        let unmodelled: Vec<&DetectedExtension> = extensions
            .iter()
            .filter(|e| !is_inert(e))
            .filter(|e| {
                // AltersAuthority blocks too. A PermanentDelegate can move the
                // balance without the owner, so "the balances moved as
                // described" says nothing about who can move them next — the
                // same reasoning as a semantics-altering extension, arriving
                // one step later.
                matches!(
                    e.impact,
                    ExtensionImpact::AltersTransferSemantics
                        | ExtensionImpact::AltersAuthority
                        | ExtensionImpact::Unknown
                ) && !(fee_modelled && is_fee_extension(e))
            })
            .collect();
        let names = |list: &[&DetectedExtension]| {
            list.iter()
                .map(|e| e.name.clone())
                .collect::<Vec<_>>()
                .join(", ")
        };
        if !unmodelled.is_empty() {
            // When a transfer-fee extension is among them, say why the model
            // could not account for it — "not modelled" is no longer the
            // whole story for that pair.
            let mut why = if unmodelled.iter().any(|e| is_fee_extension(e)) {
                fee_model
                    .not_modelled
                    .get(&delta.pubkey)
                    .map(|w| format!(". The transfer fee could not be modelled here: {w}"))
                    .unwrap_or_default()
            } else {
                String::new()
            };
            for e in &unmodelled {
                if let Some(w) = not_inert.get(&e.discriminant) {
                    why.push_str(&format!(". {}: {w}", e.name));
                }
            }
            findings.push(StateDiffFinding::critical(
                "Token2022ExtensionNotModelled",
                Some(delta.pubkey.as_str()),
                format!(
                    "this account carries Token-2022 extension(s) Graphite does not model [{}] — each can change what a transfer does without changing any field Graphite reads, so the effects observed here are arithmetic rather than behaviour and cannot be presented as verified{why}",
                    names(&unmodelled)
                ),
            ));
        } else {
            if !inert.is_empty() {
                findings.push(StateDiffFinding::warning(
                    "Token2022ExtensionInert",
                    Some(delta.pubkey.as_str()),
                    format!(
                        "extension(s) that could alter a transfer change nothing in this one — {}",
                        inert.join("; ")
                    ),
                ));
            }
            findings.push(StateDiffFinding::warning(
                "Token2022ExtensionPresent",
                Some(delta.pubkey.as_str()),
                format!(
                    "this account carries Token-2022 extension(s) [{}]; none of them redirects value unmodelled — {}",
                    names(&extensions.iter().collect::<Vec<_>>()),
                    if fee_modelled {
                        "the transfer fee is modelled and its effect is stated in the Token2022TransferFee findings"
                    } else {
                        "and none of them is modelled here"
                    }
                ),
            ));
        }
    }

    match &input.diff.artifact_accounts_undescribed {
        // The message was read. Name them.
        Some(undescribed) if !undescribed.is_empty() => {
            let shown = undescribed.len().min(8);
            findings.push(StateDiffFinding::critical(
                "ArtifactAccountsNotDescribed",
                None,
                format!(
                    "the transaction references {} account(s) this request names nowhere [{}{}] — nothing here examined what it does to them, and a state change that moves no lamports (an owner reassignment, a delegate grant, a freeze) leaves no trace a balance diff can see",
                    undescribed.len(),
                    undescribed[..shown].join(", "),
                    if undescribed.len() > shown { ", …" } else { "" }
                ),
            ));
        }
        // The message was read and every account in it is accounted for.
        Some(_) => {}
        // The message could not be read, so a count is all there is. It cannot
        // say which account is missing, and padding the description with an
        // address the transaction does not contain defeats it — which is why
        // this branch exists only for artifacts that failed to parse.
        None => {
            if let Some((artifact_accounts, described_accounts)) =
                input.diff.artifact_account_universe
            {
                if artifact_accounts > described_accounts {
                    findings.push(StateDiffFinding::critical(
                        "ArtifactAccountsNotDescribed",
                        None,
                        format!(
                            "the simulated transaction references {artifact_accounts} account(s); this request describes {described_accounts}. The {} unaccounted account(s) are named nowhere in it, so nothing here examined what the transaction does to them — and this transaction could not be parsed, so they are a count and not a list",
                            artifact_accounts - described_accounts
                        ),
                    ));
                }
            }
        }
    }

    if let Some(artifact_writes) = input.diff.artifact_balance_writes {
        let covered = input
            .diff
            .deltas
            .iter()
            .filter(|d| d.lamport_delta() != 0)
            .count();
        if covered < artifact_writes as usize {
            findings.push(StateDiffFinding::critical(
                "ArtifactEffectsNotCovered",
                None,
                format!(
                    "the simulated transaction moved lamports on {artifact_writes} account(s), but this verification examined only {covered} of them. The accounts it did not examine are not named anywhere in the request, so the verdict does not describe what these bytes do"
                ),
            ));
        }
    }

    if input.diff.covers_all_writable {
        let sum: i128 = input.diff.deltas.iter().map(|d| d.lamport_delta()).sum();
        let expected = -i128::from(fee_lamports);
        if sum != expected {
            findings.push(StateDiffFinding::critical(
                "LamportsNotConserved",
                None,
                format!(
                    "state diff claims to cover every writable account but lamport changes sum to {sum}, not {expected} (fee {fee_lamports}). Solana conserves lamports — the diff is incomplete or fabricated"
                ),
            ));
        }
    }

    for d in &changed {
        if !in_transaction.contains(d.pubkey.as_str()) {
            // A transaction can only touch accounts in its own account list, so
            // a delta on an address the instruction never named means the diff
            // does not correspond to this instruction.
            findings.push(StateDiffFinding::critical(
                "DiffAccountNotInInstruction",
                Some(&d.pubkey),
                "state diff reports a change to an account the instruction does not reference",
            ));
        }
    }

    // ── Undeclared effects ──────────────────────────────────────────────────

    // Lamports that left accounts in the diff whose balance fell, summed
    // account by account (the fee payer's fee excepted). GROSS, not net
    // (Round 29, audit 2026-10-20, F7): over a diff that covers every account
    // the transaction writes, the net is the fee and nothing else — lamports
    // are conserved — so a net figure could never report anything. It was
    // named `net_lamport_out` and worded as lamports that "left the
    // transaction's accounts", which they had not; they left the accounts
    // that fell, for accounts that rose.
    let mut gross_lamport_out: i128 = 0;
    let mut token_debit = false;
    // A token debit on a signer's account that a NAMED debit declaration does
    // not cover (F2, review of the 2026-09-29 audit's fix).
    let mut signer_debit_outside_scope: Option<String> = None;
    // A token debit on a signer's account under a debit line that names no
    // account, and no line naming this one (Round 34, R33-5).
    let mut signer_debit_under_unscoped: Option<String> = None;
    // The first token account a signer holds that was debited, whatever the
    // declaration (R30: judged when the declaration cannot be read).
    let mut signer_token_debited: Option<String> = None;
    // The signers whose account is a wallet (System-owned, no data, before
    // the transaction) — the accounts W19 judges.
    let mut signer_wallets: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    // Who signed: the transaction's own privileges where Graphite has them,
    // else the resolved accounts' signer flags.
    let signers: std::collections::HashSet<&str> = match input.diff.transaction_privileges.as_ref()
    {
        Some(p) => p.signers.iter().map(String::as_str).collect(),
        None => input
            .resolved_accounts
            .iter()
            .filter(|a| a.is_signer)
            .map(|a| a.address.as_str())
            .collect(),
    };
    // Round 34 (R33-14): the authorities of the stake accounts this
    // transaction splits from — a staker that signs, lamports that fell. A
    // created stake account carrying exactly these authorities was split
    // off an account its signer already controls; it introduces no one.
    let split_sources: Vec<Vec<(String, String)>> = changed
        .iter()
        .filter(|d| d.lamport_delta() < 0)
        .filter_map(|d| d.before.as_ref())
        .filter(|b| b.owner == STAKE_PROGRAM)
        .filter(|b| native_authority(b, "stake staker").is_some_and(|s| signers.contains(s)))
        .map(|b| b.native_authorities.clone())
        .collect();

    for d in &changed {
        let acct = Some(d.pubkey.as_str());
        let names: &[&str] = names_of
            .get(d.pubkey.as_str())
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        // Round 38 (R37-6): for an account a signer holds, an effect is
        // declared only by a line that names it. Round 34 moved the debit and
        // create judgements to `covers_by_name` (R33-5) and left these on
        // `covers`, so "updates protocol configuration or authority", a line
        // that names no account, excused a delegate granted on the signer's
        // own token account, an owner or close authority handed away, or the
        // signer's account closed. Pool and vault accounts keep `covers`: a
        // program's own state is what such a line is about.
        let held = signer_holds(d, &signers);
        let declares = |effect: &str| {
            if held {
                declared.covers_by_name(effect, names)
            } else {
                declared.covers(effect, names)
            }
        };
        let is_fee_payer = input.fee_payer == Some(d.pubkey.as_str());

        // A write to an account the transaction did not mark writable is
        // either a diff that does not match the transaction or a privilege
        // escalation. Only grounded privilege data can support a block.
        if !writable.contains(d.pubkey.as_str()) && known_accounts.contains(d.pubkey.as_str()) {
            if input.privileges_grounded {
                findings.push(StateDiffFinding::critical(
                    "WriteToReadonlyAccount",
                    acct,
                    "account changed but the transaction marked it read-only",
                ));
            } else {
                findings.push(StateDiffFinding::warning(
                    "WriteToUndeclaredWritableAccount",
                    acct,
                    "account changed but the manifest does not list it as writable (transaction AccountMeta data was not supplied, so this is reported rather than blocked)",
                ));
            }
        }

        // Ownership. Creation legitimately moves an account from the System
        // program to its owning program; a reassignment of an existing account
        // is the classic account-takeover primitive.
        // A brand-new account is not itself a loss — the rent that funds it is,
        // and the outflow check below sees that. But an account materialising
        // during an instruction that never mentions creating one is worth
        // putting in front of an operator.
        //
        // Merely gaining lamports is NOT creation: sending SOL to an address
        // that held none is what an ordinary transfer does, and reporting that
        // would fire on a large share of all legitimate traffic. A creation is
        // an account that gained *data* or left the System program's custody.
        let gained_data = d.after.as_ref().is_some_and(|s| s.data_len > 0)
            && d.before.as_ref().map(|s| s.data_len).unwrap_or(0) == 0;
        let left_system = d.after.as_ref().is_some_and(|s| s.owner != SYSTEM_PROGRAM);
        if d.was_created()
            && (gained_data || left_system)
            && !declares("create")
            && declared.is_interpretable()
        {
            findings.push(StateDiffFinding::warning(
                "UndeclaredAccountCreation",
                acct,
                format!(
                    "account created holding {} lamports; the manifest declares no account creation",
                    d.lamports_after()
                ),
            ));
        }

        if let Some((from, to)) = d.owner_change() {
            // A pre-funded, zero-data System account being handed to a program
            // is how `allocate`+`assign` builds an account — but it is also
            // exactly the `SystemProgram::Assign` takeover. The two are
            // indistinguishable from the diff alone, so the manifest breaks
            // the tie: excused only when it declares a creation. Absent that
            // declaration it is read as the takeover, which is fail-closed.
            //
            // Never for the fee payer (Round 30, found by the state-diff
            // fuzzer): it existed and held lamports before the transaction —
            // it paid the fee — so it is not an account being built, and
            // handing the signer's own wallet to a program under any
            // instruction that "initializes" something is the takeover.
            let allocation = from == SYSTEM_PROGRAM
                && d.before.as_ref().is_some_and(|s| s.data_len == 0)
                && !is_fee_payer;
            // Two ways the manifest can account for an owner change: it
            // declares the creation this allocation is part of, or it declares
            // an authority change outright. Neither means the takeover reading
            // stands.
            let declared_by_manifest = (allocation && declares("create")) || declares("authority");
            if !declared_by_manifest {
                findings.push(StateDiffFinding::critical(
                    "UndeclaredOwnerReassignment",
                    acct,
                    format!(
                        "owning program changed from {from} to {to}; the manifest declares no authority change"
                    ),
                ));
            }
        }

        // Closure.
        if d.was_closed() && !declares("close") {
            findings.push(StateDiffFinding::critical(
                "UndeclaredAccountClosure",
                acct,
                format!(
                    "account drained to zero lamports (was {}); the manifest declares no closure",
                    d.lamports_before()
                ),
            ));
        }

        // SPL delegate and close authority. Both hand a third party standing
        // permission over the account after this transaction ends, which is
        // why an undeclared one is critical rather than a note.
        if let Some(delegate) = d.delegate_granted() {
            if !declares("delegate") && !declares("authority") {
                findings.push(StateDiffFinding::critical(
                    "UndeclaredDelegateGrant",
                    acct,
                    format!(
                        "token delegate set to {delegate}; the manifest declares no delegation"
                    ),
                ));
            }
        }
        if let Some(close_authority) = d.close_authority_granted() {
            if !declares("close") && !declares("authority") {
                findings.push(StateDiffFinding::critical(
                    "UndeclaredCloseAuthorityGrant",
                    acct,
                    format!(
                        "token close authority set to {close_authority}; the manifest declares no authority change"
                    ),
                ));
            }
        }
        if d.was_frozen() && !declares("freeze") {
            findings.push(StateDiffFinding::critical(
                "UndeclaredAccountFreeze",
                acct,
                "token account frozen; the manifest declares no freeze",
            ));
        }
        // The SPL authority fields. `owner_change` above watches the owning
        // PROGRAM; these watch who controls the account inside it, and a
        // SetAuthority never touches the former. Until GFX-002 that left the
        // single most direct takeover on Solana — hand the token account to
        // somebody else and leave the balance where it is — producing a diff
        // with no findings in it: no lamports move, no delegate appears, no
        // close authority appears, nothing freezes, no supply changes, and the
        // Token program still owns the account. The layer reported clean
        // because it was not looking at the field that changed.
        if let Some((from, to)) = d.token_authority_change() {
            if !declares("authority") {
                findings.push(StateDiffFinding::critical(
                    "UndeclaredTokenAuthorityChange",
                    acct,
                    format!(
                        "token account authority changed from {from} to {to}; the manifest declares no authority change. Whoever holds it can move the entire balance after this transaction ends"
                    ),
                ));
            }
        }
        if let Some((from, to)) = d.mint_authority_change() {
            if !declares("authority") {
                findings.push(StateDiffFinding::critical(
                    "UndeclaredMintAuthorityChange",
                    acct,
                    format!(
                        "mint authority changed from {} to {}; the manifest declares no authority change. Whoever holds it can mint against this mint at will",
                        authority_label(&from),
                        authority_label(&to)
                    ),
                ));
            }
        }
        // W19 (external review): the authorities Token-2022 mint extensions
        // keep. A transfer hook's authority can point every transfer at new
        // code; a pause authority can stop every holder; a metadata or
        // group authority rewrites what the token says it is. They were
        // reported as informational extensions, never blocked.
        if let (Some(Some(b)), Some(Some(a))) = (
            d.before.as_ref().map(|s| s.token2022_powers.as_ref()),
            d.after.as_ref().map(|s| s.token2022_powers.as_ref()),
        ) {
            if b.extension_authorities != a.extension_authorities && !declares("authority") {
                let changed: Vec<String> = a
                    .extension_authorities
                    .iter()
                    .filter(|x| !b.extension_authorities.contains(x))
                    .map(|(ext, who)| {
                        format!("extension {ext} authority is now {}", authority_label(who))
                    })
                    .collect();
                findings.push(StateDiffFinding::critical(
                    "UndeclaredToken2022AuthorityChange",
                    acct,
                    format!(
                        "{}; the manifest declares no authority change. Whoever holds it controls that part of the mint after this transaction ends",
                        if changed.is_empty() {
                            "a Token-2022 extension authority was removed".to_string()
                        } else {
                            changed.join(", ")
                        }
                    ),
                ));
            }
            if b.paused != a.paused && !declares("authority") && !declares("freeze") {
                findings.push(StateDiffFinding::critical(
                    "UndeclaredToken2022Pause",
                    acct,
                    format!(
                        "the mint's paused flag changed from {:?} to {:?}; the manifest declares no authority change and no freeze. A paused mint stops every holder's transfers",
                        b.paused, a.paused
                    ),
                ));
            }
        }
        // Round 29 (audit 2026-10-20, F5): the comparison above needs the
        // powers decoded on BOTH sides, and was silently skipped when one
        // side carried an authority-bearing extension whose value could not
        // be read exactly (a wrong length, a duplicate entry) — an
        // undecodable side compared as "no change". Unless the data is
        // byte-for-byte unchanged, such a side is a finding.
        let powers_unreadable = |s: &AccountSnapshot| {
            s.owner == SPL_TOKEN_2022_PROGRAM
                && s.extensions.malformed.is_none()
                && s.token2022_powers.is_none()
                && s.extensions
                    .found
                    .iter()
                    .any(|e| EXT_AUTHORITY_BEARING.contains(&e.discriminant))
        };
        let data_unchanged = match (d.before.as_ref(), d.after.as_ref()) {
            (Some(b), Some(a)) => b.data_sha256.is_some() && b.data_sha256 == a.data_sha256,
            _ => false,
        };
        let unreadable_side = [("before", d.before.as_ref()), ("after", d.after.as_ref())]
            .into_iter()
            .find(|(_, s)| s.is_some_and(powers_unreadable))
            .map(|(side, _)| side);
        if let Some(side) = unreadable_side {
            if !data_unchanged && !declares("authority") {
                findings.push(StateDiffFinding::critical(
                    "Token2022AuthoritiesUnreadable",
                    acct,
                    format!(
                        "this Token-2022 account carries an authority-bearing extension whose value could not be read exactly {side} the transaction, and its data changed; whether an authority or the paused flag changed cannot be established, and the manifest declares no authority change"
                    ),
                ));
            }
        }
        if let Some((from, to)) = d.freeze_authority_change() {
            // A freeze authority change is an authority change; it is also the
            // thing that decides whether a freeze can ever happen, so a
            // manifest that declares freezing has accounted for it too.
            if !declares("authority") && !declares("freeze") {
                findings.push(StateDiffFinding::critical(
                    "UndeclaredFreezeAuthorityChange",
                    acct,
                    format!(
                        "freeze authority changed from {} to {}; the manifest declares no authority change and no freeze. Whoever holds it can freeze every account of this mint",
                        authority_label(&from),
                        authority_label(&to)
                    ),
                ));
            }
        }

        // A2-05 (2026-09-29 audit): what changes in DATA, not only in the
        // views decoded above. An executable flag flipping is a program
        // appearing or being retired; a native account's recorded authority
        // changing is a takeover no lamport or token field shows; a length
        // change is a realloc, reported so the reader knows the account grew.
        if let (Some(b), Some(a)) = (d.before.as_ref(), d.after.as_ref()) {
            if b.executable != a.executable {
                findings.push(StateDiffFinding::critical(
                    "ExecutableChanged",
                    acct,
                    format!(
                        "the account's executable flag changed from {} to {}",
                        b.executable, a.executable
                    ),
                ));
            }
            if b.native_authorities != a.native_authorities && !declares("authority") {
                let changed: Vec<String> = a
                    .native_authorities
                    .iter()
                    .filter(|x| !b.native_authorities.contains(x))
                    .map(|(what, who)| format!("{what} is now {who}"))
                    .collect();
                findings.push(StateDiffFinding::critical(
                    "UndeclaredNativeAuthorityChange",
                    acct,
                    format!(
                        "{}; the manifest declares no authority change. Whoever holds it controls the account after this transaction ends",
                        if changed.is_empty() {
                            "the authorities recorded in this account's data changed".to_string()
                        } else {
                            changed.join(", ")
                        }
                    ),
                ));
            }
            if b.data_len != a.data_len && a.data_len != 0 && b.data_len != 0 {
                findings.push(StateDiffFinding::warning(
                    "AccountReallocated",
                    acct,
                    format!(
                        "account data resized from {} to {} bytes",
                        b.data_len, a.data_len
                    ),
                ));
            }
        }
        // Round 34 (R33-14): authorities written into a native account this
        // transaction created or initialized. The comparison above needs a
        // before AND an after, so a stake account created with a withdrawer
        // nobody in the transaction controls — System CreateAccount of
        // 100 SOL, then Stake Initialize — handed the 100 SOL to that key
        // with no finding. Whoever a created stake, vote or nonce account
        // names can take its lamports; each must sign. No declaration
        // excuses it: "initializes accounts.stake with the stake authority"
        // says an authority is written, not that a stranger may hold it.
        if let Some(a) = d.after.as_ref() {
            let fresh = d
                .before
                .as_ref()
                .is_none_or(|b| b.native_authorities.is_empty());
            if fresh && !a.native_authorities.is_empty() {
                let strangers =
                    created_authorities_not_signing(a, &d.pubkey, &signers, &split_sources);
                if !strangers.is_empty() {
                    findings.push(StateDiffFinding::critical(
                        "CreatedAccountAuthorityNotSigner",
                        acct,
                        format!(
                            "this {} account was created or initialized by the transaction with {}, which no signer of it holds — whoever does can take its {} lamports",
                            native_kind(&a.owner),
                            strangers.join(", "),
                            a.lamports
                        ),
                    ));
                }
            }
        }

        // Mint supply.
        match d.supply_delta() {
            Some(delta) if delta > 0 && !declares("mint") => {
                findings.push(StateDiffFinding::critical(
                    "UndeclaredMint",
                    acct,
                    format!("mint supply increased by {delta}; the manifest declares no mint"),
                ));
            }
            Some(delta) if delta < 0 && !declares("burn") => {
                findings.push(StateDiffFinding::critical(
                    "UndeclaredBurn",
                    acct,
                    format!(
                        "mint supply decreased by {}; the manifest declares no burn",
                        -delta
                    ),
                ));
            }
            _ => {}
        }

        // Value movement, accumulated and judged once below
        // (`signer_lamport_losses`). The fee payer's fee-sized outflow is
        // expected on every transaction and is excluded.
        let lam = d.lamport_delta();
        let fee = i128::from(fee_lamports);
        if signers.contains(d.pubkey.as_str())
            && d.before
                .as_ref()
                .is_some_and(|s| s.owner == SYSTEM_PROGRAM && s.data_len == 0)
        {
            signer_wallets.insert(d.pubkey.as_str());
        }
        if lam < 0 {
            let magnitude = -lam;
            if !(is_fee_payer && magnitude <= fee) {
                gross_lamport_out += magnitude - if is_fee_payer { fee } else { 0 };
            }
        }
        // F2: a closure that took a balance with it is a debit too.
        if d.token_debit().is_some_and(|t| t > 0) {
            token_debit = true;
            // A debit declared about named accounts (`debits accounts.vault`)
            // excuses those accounts. A token account a SIGNER owns that the
            // declaration does not name is the user's other money: the
            // scenario is a primary that declares a debit of one vault and a
            // sibling that drains the user's other token account. Accounts
            // owned by programs (pool vaults paying out a swap) are not
            // signers' and keep the transaction-wide judgement below.
            let owner = d
                .before
                .as_ref()
                .and_then(|s| s.token.as_ref())
                .map(|t| t.owner.as_str());
            if owner.is_some_and(|o| signers.contains(o)) && signer_token_debited.is_none() {
                signer_token_debited = Some(d.pubkey.clone());
            }
            // Round 34 (R33-5): only a line that NAMES this account declares
            // its debit. A line naming no account ("transfers funds between
            // the protocol and the involved accounts") says nothing about
            // whose tokens: for a signer's account it is judged as a
            // declaration Graphite cannot read, below.
            if declared.debit
                && !declared.covers_by_name("debit", names)
                && owner.is_some_and(|o| signers.contains(o))
            {
                if declared.debit_names_no_account() {
                    if signer_debit_under_unscoped.is_none() {
                        signer_debit_under_unscoped = Some(d.pubkey.clone());
                    }
                } else if signer_debit_outside_scope.is_none() {
                    signer_debit_outside_scope = Some(d.pubkey.clone());
                }
            }
        }
    }

    // Round 34 (R33-6, R33-7, R33-10): what each signer lost, its own.
    let fee = i128::from(fee_lamports);
    let reviewed_creator = |owner: &str| {
        owner == SPL_TOKEN_PROGRAM
            || owner == SPL_TOKEN_2022_PROGRAM
            || declared.instruction_program.as_deref() == Some(owner)
    };
    let losses = signer_lamport_losses(
        &changed,
        &signers,
        input.fee_payer,
        fee,
        &|d: &AccountDelta| {
            let names: &[&str] = names_of
                .get(d.pubkey.as_str())
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            declared.covers_by_name("create", names)
                && d.after.as_ref().is_some_and(|a| reviewed_creator(&a.owner))
        },
    );
    let names_of_signer = |s: &str| -> Vec<&str> { names_of.get(s).cloned().unwrap_or_default() };
    // W19 and its Round 34 sibling: a signer's wallet whose loss no debit
    // line NAMING it declares. Under a declaration whose only debit lines
    // name other accounts that is W19; under one with a line that names no
    // account, it is a loss under a declaration Graphite cannot read (R33-5).
    let (mut signer_lamports_outside_scope, mut signer_lamports_unscoped): (i128, i128) = (0, 0);
    // R33-15: a wallet the located instruction's data debits by a stated
    // amount, which lost more.
    let mut beyond_stated: Vec<(String, u64, i128)> = Vec::new();
    for (signer, loss) in &losses {
        let unexplained = &loss.unexplained;
        let names = names_of_signer(signer);
        let named = declared.covers_by_name("debit", &names);
        if let Some((_, amount)) = declared.lamport_amounts.iter().find(|(a, _)| a == signer) {
            // The stated amount already pays the rent of what the located
            // instruction creates — a stated amount comes only from a System
            // `Transfer` or `CreateAccount`, and only a `CreateAccount`
            // declares a creation. Netting that rent out again before the
            // comparison counted it twice (Round 37, R37-7).
            let lost = unexplained + loss.rent;
            if named && lost > i128::from(*amount) {
                beyond_stated.push((signer.clone(), *amount, lost));
            }
        }
        if !declared.debit || named || !signer_wallets.contains(signer.as_str()) {
            continue;
        }
        if *unexplained > 0 {
            if declared.debit_names_no_account() {
                signer_lamports_unscoped += unexplained;
            } else {
                signer_lamports_outside_scope += unexplained;
            }
        }
    }
    let signer_net_loss: i128 = losses.values().map(|u| u.unexplained.max(0)).sum();
    // The Round 30/32 rule for a declaration Graphite cannot read, applied
    // to a debit line that names no account (R33-5).
    let unscoped_relaxed = relax.unreadable_value_declarations && declared.class_moves_value();
    let unscoped_class = match declared.security_class.as_deref() {
        Some(c) if declared.class_moves_value() => format!(
            "{c:?}{}",
            if unscoped_relaxed {
                " (GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS is on)"
            } else {
                " (GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS is off)"
            }
        ),
        Some(c) => format!("{c:?}, not one that moves value"),
        None => "not stated".to_string(),
    };
    if signer_lamports_unscoped > 0 {
        let detail = format!(
            "{signer_lamports_unscoped} lamports left a signer's own wallet beyond the fee, what stayed the signer's and the rent of accounts this instruction declares it creates; the manifest's debit names no account, so it does not say this wallet's lamports may leave, and a declaration Graphite cannot read does not excuse a signer's loss (security class {unscoped_class})"
        );
        findings.push(if unscoped_relaxed {
            StateDiffFinding::warning("SignerLamportsUnderUnscopedDebit", None, detail)
        } else {
            StateDiffFinding::critical("SignerLamportsUnderUnscopedDebit", None, detail)
        });
    }
    if let Some(account) = signer_debit_under_unscoped {
        let detail = format!(
            "a token account a signer owns was debited; the manifest's debit names no account, so it does not say this account's tokens may leave, and a declaration Graphite cannot read does not excuse a signer's loss (security class {unscoped_class})"
        );
        findings.push(if unscoped_relaxed {
            StateDiffFinding::warning("SignerTokenDebitUnderUnscopedDebit", Some(&account), detail)
        } else {
            StateDiffFinding::critical("SignerTokenDebitUnderUnscopedDebit", Some(&account), detail)
        });
    }
    for (signer, amount, lost) in beyond_stated {
        let detail = format!(
            "{lost} lamports left this signer's wallet beyond the fee and what stayed the signer's; the located instruction's data debits it by {amount}, which already pays the rent of any account it creates, so {} lamports more left than the instruction states",
            lost - i128::from(amount)
        );
        findings.push(if relax.signer_lamports_outside_declared_debit {
            StateDiffFinding::warning("SignerLamportsBeyondDeclaredAmount", Some(&signer), detail)
        } else {
            StateDiffFinding::critical("SignerLamportsBeyondDeclaredAmount", Some(&signer), detail)
        });
    }

    // W19 (Round 32): the signers' lamports that left beyond the fee, less
    // what stayed theirs or paid rent for an account the transaction created.
    // Until Round 32 this was a warning ("disclosed, not refused"): the
    // declaration names the accounts it debits, a signer's wallet is not one
    // of them, and nothing else in L4 judged the loss — a primary declaring a
    // debit of `accounts.user_token` let a sibling empty the signer's SOL with
    // a warning. The operator can restore the warning
    // (`L4Relaxations::signer_lamports_outside_declared_debit`). Round 34:
    // per signer, and only what stayed THAT signer's is netted out.
    signer_lamports_outside_scope = signer_lamports_outside_scope.max(0);
    if signer_lamports_outside_scope > 0 {
        let detail = format!(
            "{signer_lamports_outside_scope} lamports left a signer's own wallet beyond the fee, what stayed the signer's and the rent of accounts this instruction declares it creates; the manifest declares a debit only of other accounts"
        );
        findings.push(if relax.signer_lamports_outside_declared_debit {
            StateDiffFinding::warning("SignerLamportsOutsideDeclaredDebit", None, detail)
        } else {
            StateDiffFinding::critical("SignerLamportsOutsideDeclaredDebit", None, detail)
        });
    }

    if let Some(account) = signer_debit_outside_scope {
        findings.push(StateDiffFinding::critical(
            "UndeclaredTokenDebit",
            Some(account.as_str()),
            "a token account a signer owns was debited, and the manifest declares a debit only of other accounts",
        ));
    }

    // Value movement the declaration does not account for. An interpretable
    // declaration with no debit is judged strictly.
    //
    // R30: a declaration that is silent, or whose prose Graphite cannot read,
    // let any of it through with at most a warning — "a manifest that
    // promises nothing cannot be contradicted", and wording Graphite does not
    // know should not block a protocol (P12). That holds for value moving
    // between other accounts (a pool paying out). It does not hold for the
    // SIGNER's value, which is what the verdict is for: a declaration that
    // says nothing Graphite can read cannot excuse a signer's loss, so that
    // loss is Critical — unless the manifest's security class for the
    // instruction is one that moves value (`class_moves_value`), when the
    // unread prose may well describe it and it is reported as before.
    // Measured on the shipped manifests at R30: no declaration is silent; 382
    // cannot be read, 227 of them `inert` or `authority`, which then blocked
    // a signer's loss, and 155 kept the warning.
    //
    // Round 32: the production default. A declaration Graphite cannot read
    // cannot excuse a signer's loss whatever its class: "Orca Whirlpools
    // instruction" says nothing about whose tokens leave. Sixteen of the 155
    // were rewritten from their programs' IDLs so they can be read; for the
    // other 139 the operator may restore the Round 30 warning
    // (`L4Relaxations::unreadable_value_declarations`). Counts pinned in
    // `tests/r30_declared_effects_census.rs`.
    if !declared.debit {
        let strict = declared.is_interpretable();
        let signer_strict =
            strict || !(relax.unreadable_value_declarations && declared.class_moves_value());
        let unread = format!(
            "{}, and its security class is {} — a declaration Graphite cannot read does not excuse a signer's loss",
            if declared.is_silent() {
                "the manifest declares no state change for this instruction"
            } else {
                "none of the manifest's declared changes could be interpreted"
            },
            match declared.security_class.as_deref() {
                Some(c) if declared.class_moves_value() => format!(
                    "{c:?} (GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS is off)"
                ),
                Some(c) => format!("{c:?}, not one that moves value"),
                None => "not stated".to_string(),
            }
        );
        if token_debit {
            let detail = "token balances decreased but the manifest declares no debit";
            if strict {
                findings.push(StateDiffFinding::critical(
                    "UndeclaredTokenDebit",
                    None,
                    detail,
                ));
            } else if let (true, Some(account)) = (signer_strict, signer_token_debited.as_deref()) {
                findings.push(StateDiffFinding::critical(
                    "UndeclaredTokenDebit",
                    Some(account),
                    format!("a token account a signer holds was debited; {unread}"),
                ));
            } else if !declared.is_silent() {
                findings.push(StateDiffFinding::warning(
                    "UninterpretableDeclarationWithTokenDebit",
                    None,
                    format!("{detail} — and none of its declared changes could be interpreted, so this is reported rather than blocked"),
                ));
            }
        }
        // F7: the signers' own lamports are value too. A token debit under a
        // manifest that declares no debit is Critical, and so — by the same
        // rule, observed but undeclared — is a signer's net lamport loss
        // beyond the fee and the rent of accounts this transaction created.
        // It used to be at most a Warning ("UnexplainedLamportOutflow"), and
        // switched off entirely when the manifest declared any creation or
        // closure: an instruction promising to close an account could carry
        // a sibling that emptied the signer's wallet, and L4 said nothing.
        // Scope (P14): the declaration judged is the located instruction's,
        // so a tip or transfer made by a SIBLING instruction under a primary
        // that declares no debit now blocks; the finding names the amount.
        if signer_net_loss > 0 {
            let detail = format!(
                "the transaction's signers lose {signer_net_loss} lamports beyond the fee, what stayed each signer's own and the rent of accounts this instruction declares it creates (counted per signer: one signer's gain does not offset another's loss), but the manifest declares no debit"
            );
            if strict {
                findings.push(StateDiffFinding::critical(
                    "UndeclaredSignerLamportDebit",
                    None,
                    detail,
                ));
            } else if signer_strict {
                findings.push(StateDiffFinding::critical(
                    "UndeclaredSignerLamportDebit",
                    None,
                    format!("{detail}; {unread}"),
                ));
            } else if !declared.is_silent() {
                findings.push(StateDiffFinding::warning(
                    "UninterpretableDeclarationWithSignerLamportDebit",
                    None,
                    format!("{detail} — and none of its declared changes could be interpreted, so this is reported rather than blocked"),
                ));
            }
        } else if !declared.is_silent()
            && !token_debit
            && gross_lamport_out > 0
            && !declared.create
            && !declared.close
        {
            // Account creation legitimately debits the payer for rent, and a
            // closure legitimately moves the whole balance out, so neither is
            // reported as an unexplained outflow.
            findings.push(StateDiffFinding::warning(
                "UnexplainedLamportOutflow",
                None,
                format!(
                    "{gross_lamport_out} lamports left accounts in this diff (summed over every account whose balance fell, beyond the fee); the manifest declares no debit"
                ),
            ));
        }
    }

    let empty = changed.is_empty();
    if empty && !input.expected_state_changes.is_empty() {
        findings.push(StateDiffFinding::warning(
            "NoObservedStateChange",
            None,
            "the manifest declares state changes but the diff shows none — the transaction is a no-op, or the diff does not reflect it",
        ));
    }

    let blocked = findings
        .iter()
        .any(|f| f.severity == DiffSeverity::Critical);

    StateDiffReport {
        findings,
        changed_accounts: changed.len(),
        blocked,
        empty,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_resolution::{AccountIdentity, ResolvedAccount};

    const ALICE: &str = "A1ice11111111111111111111111111111111111111";
    const BOB: &str = "B0b11111111111111111111111111111111111111111";
    const ATTACKER: &str = "Attacker1111111111111111111111111111111111";

    fn account(address: &str, writable: bool) -> ResolvedAccount {
        ResolvedAccount {
            address: address.to_string(),
            role: "account".to_string(),
            name: String::new(),
            is_pda: false,
            is_signer: false,
            is_writable: writable,
            pda_seeds: vec![],
            identity: AccountIdentity::Unverified,
            expected_address_mismatch: false,
            pda_mismatch: false,
            privilege_mismatch: false,
        }
    }

    fn lamport_snapshot(pubkey: &str, lamports: u64) -> AccountSnapshot {
        AccountSnapshot {
            pubkey: pubkey.to_string(),
            lamports,
            owner: SYSTEM_PROGRAM.to_string(),
            data_len: 0,
            token: None,
            mint: None,
            extensions: Default::default(),
            transfer_fee_withheld: None,
            transfer_fee_config: None,
            token2022_powers: None,
            data_sha256: None,
            executable: false,
            native_authorities: Vec::new(),
        }
    }

    /// Build the 165-byte SPL token account layout so tests exercise the real
    /// decoder rather than a hand-built `TokenAccountView`.
    fn token_account_bytes(
        mint: &[u8; 32],
        owner: &[u8; 32],
        amount: u64,
        delegate: Option<&[u8; 32]>,
        state: u8,
        close_authority: Option<&[u8; 32]>,
    ) -> Vec<u8> {
        let mut d = vec![0u8; TOKEN_ACCOUNT_LEN];
        d[0..32].copy_from_slice(mint);
        d[32..64].copy_from_slice(owner);
        d[64..72].copy_from_slice(&amount.to_le_bytes());
        if let Some(del) = delegate {
            d[72..76].copy_from_slice(&1u32.to_le_bytes());
            d[76..108].copy_from_slice(del);
        }
        d[108] = state;
        if let Some(ca) = close_authority {
            d[129..133].copy_from_slice(&1u32.to_le_bytes());
            d[133..165].copy_from_slice(ca);
        }
        d
    }

    fn mint_bytes(supply: u64, decimals: u8) -> Vec<u8> {
        let mut d = vec![0u8; MINT_LEN];
        d[36..44].copy_from_slice(&supply.to_le_bytes());
        d[44] = decimals;
        d[45] = 1; // is_initialized
        d
    }

    /// The same layout with its two authorities filled in. `mint_authority` is
    /// a `COption<Pubkey>` at offset 0 and `freeze_authority` one at offset 46;
    /// `None` leaves the tag at zero, which is how a revoked authority is
    /// written on chain.
    fn mint_bytes_with_authorities(
        supply: u64,
        mint_authority: Option<&[u8; 32]>,
        freeze_authority: Option<&[u8; 32]>,
    ) -> Vec<u8> {
        let mut d = mint_bytes(supply, 6);
        if let Some(a) = mint_authority {
            d[0..4].copy_from_slice(&1u32.to_le_bytes());
            d[4..36].copy_from_slice(a);
        }
        if let Some(a) = freeze_authority {
            d[46..50].copy_from_slice(&1u32.to_le_bytes());
            d[50..82].copy_from_slice(a);
        }
        d
    }

    fn token_snapshot(pubkey: &str, lamports: u64, data: &[u8]) -> AccountSnapshot {
        AccountSnapshot::from_raw(pubkey, lamports, SPL_TOKEN_PROGRAM, data)
    }

    fn check<'a>(
        diff: &'a StateDiff,
        accounts: &'a [ResolvedAccount],
        declared: &'a [String],
    ) -> StateDiffReport {
        check_state_diff(&StateDiffCheck {
            diff,
            resolved_accounts: accounts,
            privileges_grounded: true,
            expected_state_changes: declared,
            fee_payer: Some(ALICE),
        })
    }

    fn codes(report: &StateDiffReport) -> Vec<&str> {
        report.findings.iter().map(|f| f.code.as_str()).collect()
    }

    // ── Decoders ────────────────────────────────────────────────────────────

    #[test]
    fn token_account_decodes_amount_delegate_and_close_authority() {
        let mint = [7u8; 32];
        let owner = [9u8; 32];
        let delegate = [3u8; 32];
        let close = [4u8; 32];
        let data = token_account_bytes(&mint, &owner, 5_000, Some(&delegate), 1, Some(&close));
        let view = decode_token_account(&data).expect("165-byte account must decode");
        assert_eq!(view.amount, 5_000);
        assert_eq!(view.mint, bs58::encode(mint).into_string());
        assert_eq!(view.owner, bs58::encode(owner).into_string());
        assert_eq!(view.delegate, Some(bs58::encode(delegate).into_string()));
        assert_eq!(
            view.close_authority,
            Some(bs58::encode(close).into_string())
        );
        assert!(!view.is_frozen());
    }

    #[test]
    fn a_token_account_never_decodes_as_a_mint() {
        // The dangerous confusion: a 165-byte token account is longer than the
        // 82-byte mint layout, so a length-only check would read its `owner`
        // field as a supply and report a phantom mint.
        let data = token_account_bytes(&[1u8; 32], &[2u8; 32], 42, None, 1, None);
        assert!(decode_token_account(&data).is_some());
        assert!(
            decode_mint(&data).is_none(),
            "a token account must not decode as a mint"
        );
    }

    #[test]
    fn a_mint_never_decodes_as_a_token_account() {
        let data = mint_bytes(1_000_000, 6);
        assert!(decode_mint(&data).is_some());
        assert!(decode_token_account(&data).is_none());
    }

    #[test]
    fn token_2022_type_byte_disambiguates_extended_accounts() {
        // Both are longer than 165 bytes; only the type byte tells them apart.
        let mut extended_account = token_account_bytes(&[1u8; 32], &[2u8; 32], 7, None, 1, None);
        extended_account.push(T22_TYPE_ACCOUNT);
        extended_account.extend_from_slice(&[0u8; 16]);
        assert!(decode_token_account(&extended_account).is_some());
        assert!(decode_mint(&extended_account).is_none());

        let mut extended_mint = mint_bytes(500, 9);
        extended_mint.resize(TOKEN_ACCOUNT_LEN, 0);
        extended_mint.push(T22_TYPE_MINT);
        extended_mint.extend_from_slice(&[0u8; 16]);
        assert!(decode_mint(&extended_mint).is_some());
        assert!(decode_token_account(&extended_mint).is_none());
    }

    #[test]
    fn uninitialized_accounts_do_not_decode() {
        let data = token_account_bytes(&[1u8; 32], &[2u8; 32], 0, None, 0, None);
        assert!(decode_token_account(&data).is_none());
        let mut mint = mint_bytes(10, 6);
        mint[45] = 0;
        assert!(decode_mint(&mint).is_none());
    }

    #[test]
    fn a_null_coption_pubkey_reads_as_none() {
        // Tag says Some, key is all zeroes. Reporting that as a real delegate
        // would fire UndeclaredDelegateGrant on every account that has ever
        // had one revoked.
        let mut data = token_account_bytes(&[1u8; 32], &[2u8; 32], 1, None, 1, None);
        data[72..76].copy_from_slice(&1u32.to_le_bytes());
        // bytes 76..108 stay zero
        let view = decode_token_account(&data).unwrap();
        assert_eq!(view.delegate, None);
    }

    #[test]
    fn truncated_data_never_panics() {
        for len in 0..MINT_LEN {
            let data = vec![0xABu8; len];
            assert!(decode_token_account(&data).is_none());
            assert!(decode_mint(&data).is_none());
        }
        // And a snapshot of garbage owned by the token program is still safe.
        let s = AccountSnapshot::from_raw("x", 1, SPL_TOKEN_PROGRAM, &[0xFF; 100]);
        assert!(s.token.is_none() && s.mint.is_none());
    }

    // ── Diff integrity ──────────────────────────────────────────────────────

    #[test]
    fn lamports_that_do_not_conserve_fail_a_complete_diff() {
        // 1000 leaves Alice, only 400 arrives at Bob, fee is 5. 600 lamports
        // are unaccounted for: the diff cannot be true.
        let diff = StateDiff {
            deltas: vec![
                AccountDelta {
                    pubkey: ALICE.to_string(),
                    before: Some(lamport_snapshot(ALICE, 10_000)),
                    after: Some(lamport_snapshot(ALICE, 9_000)),
                },
                AccountDelta {
                    pubkey: BOB.to_string(),
                    before: Some(lamport_snapshot(BOB, 0)),
                    after: Some(lamport_snapshot(BOB, 400)),
                },
            ],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 5,
            covers_all_writable: true,
            // No artifact was simulated in this fixture, so there is no
            // measured effect count to compare coverage against.
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(ALICE, true), account(BOB, true)];
        let report = check(&diff, &accounts, &["debit source".to_string()]);
        assert!(report.blocked);
        assert!(codes(&report).contains(&"LamportsNotConserved"));
    }

    #[test]
    fn a_conserving_transfer_raises_nothing() {
        let diff = StateDiff {
            deltas: vec![
                AccountDelta {
                    pubkey: ALICE.to_string(),
                    before: Some(lamport_snapshot(ALICE, 10_000)),
                    after: Some(lamport_snapshot(ALICE, 8_995)),
                },
                AccountDelta {
                    pubkey: BOB.to_string(),
                    before: Some(lamport_snapshot(BOB, 0)),
                    after: Some(lamport_snapshot(BOB, 1_000)),
                },
            ],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 5,
            covers_all_writable: true,
            // No artifact was simulated in this fixture, so there is no
            // measured effect count to compare coverage against.
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(ALICE, true), account(BOB, true)];
        let report = check(
            &diff,
            &accounts,
            &[
                "debit source account".to_string(),
                "credit destination".to_string(),
            ],
        );
        assert!(
            report.findings.is_empty(),
            "a plain declared transfer must be clean, got {:?}",
            report.findings
        );
    }

    #[test]
    fn a_partial_diff_is_not_held_to_conservation() {
        // Same unbalanced numbers as above, but the diff does not claim to be
        // complete — holding it to the identity would be a false positive.
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: ALICE.to_string(),
                before: Some(lamport_snapshot(ALICE, 10_000)),
                after: Some(lamport_snapshot(ALICE, 9_000)),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 5,
            covers_all_writable: false,
            // No artifact was simulated in this fixture, so there is no
            // measured effect count to compare coverage against.
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(ALICE, true)];
        let report = check(&diff, &accounts, &["debit source".to_string()]);
        assert!(!codes(&report).contains(&"LamportsNotConserved"));
    }

    #[test]
    fn a_delta_on_an_account_the_instruction_never_named_is_critical() {
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: ATTACKER.to_string(),
                before: Some(lamport_snapshot(ATTACKER, 0)),
                after: Some(lamport_snapshot(ATTACKER, 999)),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            // No artifact was simulated in this fixture, so there is no
            // measured effect count to compare coverage against.
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(ALICE, true)];
        let report = check(&diff, &accounts, &["debit source".to_string()]);
        assert!(report.blocked);
        assert!(codes(&report).contains(&"DiffAccountNotInInstruction"));
    }

    // ── Undeclared effects ──────────────────────────────────────────────────

    #[test]
    fn an_owner_reassignment_during_a_transfer_is_critical() {
        // The takeover primitive: the instruction says "transfer", the diff
        // shows the account handed to another program.
        let mut after = lamport_snapshot(ALICE, 10_000);
        after.owner = ATTACKER.to_string();
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: ALICE.to_string(),
                before: Some(lamport_snapshot(ALICE, 10_000)),
                after: Some(after),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            // No artifact was simulated in this fixture, so there is no
            // measured effect count to compare coverage against.
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(ALICE, true)];
        let report = check(&diff, &accounts, &["debit source, credit dest".to_string()]);
        assert!(report.blocked);
        assert!(codes(&report).contains(&"UndeclaredOwnerReassignment"));
    }

    #[test]
    fn an_owner_change_is_allowed_when_the_manifest_declares_an_authority_change() {
        let mut after = lamport_snapshot(ALICE, 10_000);
        after.owner = BOB.to_string();
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: ALICE.to_string(),
                before: Some(lamport_snapshot(ALICE, 10_000)),
                after: Some(after),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            // No artifact was simulated in this fixture, so there is no
            // measured effect count to compare coverage against.
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(ALICE, true)];
        let report = check(
            &diff,
            &accounts,
            &["assign new authority to the account".to_string()],
        );
        assert!(!codes(&report).contains(&"UndeclaredOwnerReassignment"));
    }

    // ── GFX-002: the authority fields ───────────────────────────────────────
    //
    // `owner_change` above watches the account's owning PROGRAM. The SPL
    // `owner` field — who may move the balance — is a different field with
    // the same word for it, and nothing was watching it. A
    // `SetAuthority(AccountOwner)` leaves the Token program exactly where it
    // was, moves no lamports, grants no delegate, sets no close authority,
    // freezes nothing and changes no supply: every check this module had came
    // back empty on the most direct account takeover there is. Confirmed
    // against `eaee998` — a diff whose only change was the token account's
    // owner returned `findings: []`, `blocked: false`, under both generic and
    // transfer prose.

    #[test]
    fn a_token_account_changing_hands_is_critical() {
        let before = token_account_bytes(&[1u8; 32], &[2u8; 32], 1_000, None, 1, None);
        // Same mint, same balance, same everything — except who owns it.
        let after = token_account_bytes(&[1u8; 32], &[66u8; 32], 1_000, None, 1, None);
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: ALICE.to_string(),
                before: Some(token_snapshot(ALICE, 2_039_280, &before)),
                after: Some(token_snapshot(ALICE, 2_039_280, &after)),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(ALICE, true)];
        let report = check(&diff, &accounts, &["debit source, credit dest".to_string()]);
        assert!(
            report.blocked,
            "the account changed hands and the diff reported: {:?}",
            report.findings
        );
        assert!(codes(&report).contains(&"UndeclaredTokenAuthorityChange"));
    }

    /// The same change under a manifest that says it is coming is not a
    /// finding. Without this, "block everything" would pass the test above.
    #[test]
    fn a_declared_authority_change_may_move_a_token_account() {
        let before = token_account_bytes(&[1u8; 32], &[2u8; 32], 1_000, None, 1, None);
        let after = token_account_bytes(&[1u8; 32], &[66u8; 32], 1_000, None, 1, None);
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: ALICE.to_string(),
                before: Some(token_snapshot(ALICE, 2_039_280, &before)),
                after: Some(token_snapshot(ALICE, 2_039_280, &after)),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        // The declaration is scoped to `accounts.account_or_mint` (A2-01), so
        // the account must hold that slot, as SetAuthority's resolved account
        // does. The same change on an account in no named slot stays a
        // finding, which is the next assertion.
        let named = ResolvedAccount {
            name: "account_or_mint".to_string(),
            ..account(ALICE, true)
        };
        let declaration =
            ["changes authority (owner, mint_authority, freeze_authority) of accounts.account_or_mint".to_string()];
        let report = check(&diff, &[named], &declaration);
        assert!(!codes(&report).contains(&"UndeclaredTokenAuthorityChange"));
        let unnamed = check(&diff, &[account(ALICE, true)], &declaration);
        assert!(codes(&unnamed).contains(&"UndeclaredTokenAuthorityChange"));
    }

    /// An ordinary transfer moves the balance and nothing else. The new check
    /// must not fire on it.
    #[test]
    fn an_ordinary_transfer_is_not_an_authority_change() {
        let before = token_account_bytes(&[1u8; 32], &[2u8; 32], 1_000, None, 1, None);
        let after = token_account_bytes(&[1u8; 32], &[2u8; 32], 400, None, 1, None);
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: ALICE.to_string(),
                before: Some(token_snapshot(ALICE, 2_039_280, &before)),
                after: Some(token_snapshot(ALICE, 2_039_280, &after)),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(ALICE, true)];
        let report = check(
            &diff,
            &accounts,
            &["debits accounts.source token balance".to_string()],
        );
        assert!(!codes(&report).contains(&"UndeclaredTokenAuthorityChange"));
    }

    /// Initializing a pre-allocated account is a creation, not a hand-over.
    /// `decode_token_account` refuses state 0, so the "before" side does not
    /// decode and there is no authority to have changed.
    #[test]
    fn initializing_an_account_is_not_an_authority_change() {
        let before = token_account_bytes(&[0u8; 32], &[0u8; 32], 0, None, 0, None);
        let after = token_account_bytes(&[1u8; 32], &[2u8; 32], 0, None, 1, None);
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: ALICE.to_string(),
                before: Some(token_snapshot(ALICE, 2_039_280, &before)),
                after: Some(token_snapshot(ALICE, 2_039_280, &after)),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(ALICE, true)];
        let report = check(
            &diff,
            &accounts,
            &["initializes accounts.account".to_string()],
        );
        assert!(!codes(&report).contains(&"UndeclaredTokenAuthorityChange"));
    }

    #[test]
    fn a_mint_authority_changing_hands_is_critical() {
        let before = mint_bytes_with_authorities(1_000_000, Some(&[2u8; 32]), None);
        let after = mint_bytes_with_authorities(1_000_000, Some(&[66u8; 32]), None);
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: BOB.to_string(),
                before: Some(token_snapshot(BOB, 1_461_600, &before)),
                after: Some(token_snapshot(BOB, 1_461_600, &after)),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(BOB, true)];
        let report = check(&diff, &accounts, &["debit source, credit dest".to_string()]);
        assert!(
            report.blocked,
            "the mint changed hands and the diff reported: {:?}",
            report.findings
        );
        assert!(codes(&report).contains(&"UndeclaredMintAuthorityChange"));
    }

    /// Absence is a value. A mint that gains a freeze authority it did not
    /// have gains the ability to freeze every account of that mint, and a
    /// comparison that required a key on both sides would report nothing.
    #[test]
    fn a_freeze_authority_appearing_from_nothing_is_critical() {
        let before = mint_bytes_with_authorities(1_000_000, Some(&[2u8; 32]), None);
        let after = mint_bytes_with_authorities(1_000_000, Some(&[2u8; 32]), Some(&[66u8; 32]));
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: BOB.to_string(),
                before: Some(token_snapshot(BOB, 1_461_600, &before)),
                after: Some(token_snapshot(BOB, 1_461_600, &after)),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(BOB, true)];
        let report = check(&diff, &accounts, &["debit source, credit dest".to_string()]);
        assert!(report.blocked, "{:?}", report.findings);
        assert!(codes(&report).contains(&"UndeclaredFreezeAuthorityChange"));
    }

    /// A mint whose authorities are untouched produces no authority finding,
    /// however much its supply moves.
    #[test]
    fn a_declared_mint_is_not_an_authority_change() {
        let before = mint_bytes_with_authorities(1_000_000, Some(&[2u8; 32]), None);
        let after = mint_bytes_with_authorities(1_500_000, Some(&[2u8; 32]), None);
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: BOB.to_string(),
                before: Some(token_snapshot(BOB, 1_461_600, &before)),
                after: Some(token_snapshot(BOB, 1_461_600, &after)),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(BOB, true)];
        let report = check(
            &diff,
            &accounts,
            &[
                "credits accounts.account token balance by data.amount".to_string(),
                "updates mint supply by data.amount".to_string(),
            ],
        );
        assert!(!codes(&report).contains(&"UndeclaredMintAuthorityChange"));
        assert!(!codes(&report).contains(&"UndeclaredFreezeAuthorityChange"));
    }

    #[test]
    fn a_delegate_granted_during_a_swap_is_critical() {
        // The approval-drain primitive: the swap works, and quietly leaves the
        // attacker with standing permission to move the tokens later.
        let before_bytes = token_account_bytes(&[1u8; 32], &[2u8; 32], 1_000, None, 1, None);
        let after_bytes =
            token_account_bytes(&[1u8; 32], &[2u8; 32], 1_000, Some(&[66u8; 32]), 1, None);
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: ALICE.to_string(),
                before: Some(token_snapshot(ALICE, 2_039_280, &before_bytes)),
                after: Some(token_snapshot(ALICE, 2_039_280, &after_bytes)),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            // No artifact was simulated in this fixture, so there is no
            // measured effect count to compare coverage against.
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(ALICE, true)];
        let report = check(
            &diff,
            &accounts,
            &["swap input token for output token".to_string()],
        );
        assert!(report.blocked);
        assert!(codes(&report).contains(&"UndeclaredDelegateGrant"));
    }

    #[test]
    fn a_declared_approve_may_grant_a_delegate() {
        let before_bytes = token_account_bytes(&[1u8; 32], &[2u8; 32], 1_000, None, 1, None);
        let after_bytes =
            token_account_bytes(&[1u8; 32], &[2u8; 32], 1_000, Some(&[66u8; 32]), 1, None);
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: ALICE.to_string(),
                before: Some(token_snapshot(ALICE, 2_039_280, &before_bytes)),
                after: Some(token_snapshot(ALICE, 2_039_280, &after_bytes)),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            // No artifact was simulated in this fixture, so there is no
            // measured effect count to compare coverage against.
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(ALICE, true)];
        let report = check(
            &diff,
            &accounts,
            &["approve a delegate for the token account".to_string()],
        );
        assert!(report.findings.is_empty(), "got {:?}", report.findings);
    }

    #[test]
    fn a_close_authority_granted_during_a_transfer_is_critical() {
        let before_bytes = token_account_bytes(&[1u8; 32], &[2u8; 32], 1_000, None, 1, None);
        let after_bytes =
            token_account_bytes(&[1u8; 32], &[2u8; 32], 1_000, None, 1, Some(&[77u8; 32]));
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: ALICE.to_string(),
                before: Some(token_snapshot(ALICE, 2_039_280, &before_bytes)),
                after: Some(token_snapshot(ALICE, 2_039_280, &after_bytes)),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            // No artifact was simulated in this fixture, so there is no
            // measured effect count to compare coverage against.
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(ALICE, true)];
        let report = check(&diff, &accounts, &["transfer tokens".to_string()]);
        assert!(codes(&report).contains(&"UndeclaredCloseAuthorityGrant"));
    }

    #[test]
    fn an_undeclared_freeze_is_critical() {
        let before_bytes = token_account_bytes(&[1u8; 32], &[2u8; 32], 1_000, None, 1, None);
        let after_bytes = token_account_bytes(&[1u8; 32], &[2u8; 32], 1_000, None, 2, None);
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: ALICE.to_string(),
                before: Some(token_snapshot(ALICE, 2_039_280, &before_bytes)),
                after: Some(token_snapshot(ALICE, 2_039_280, &after_bytes)),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            // No artifact was simulated in this fixture, so there is no
            // measured effect count to compare coverage against.
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(ALICE, true)];
        let report = check(&diff, &accounts, &["transfer tokens".to_string()]);
        assert!(codes(&report).contains(&"UndeclaredAccountFreeze"));
    }

    #[test]
    fn an_undeclared_supply_increase_is_a_mint_finding() {
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: ALICE.to_string(),
                before: Some(token_snapshot(ALICE, 1_461_600, &mint_bytes(1_000, 6))),
                after: Some(token_snapshot(
                    ALICE,
                    1_461_600,
                    &mint_bytes(1_000_000_000, 6),
                )),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            // No artifact was simulated in this fixture, so there is no
            // measured effect count to compare coverage against.
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(ALICE, true)];
        let report = check(&diff, &accounts, &["transfer tokens".to_string()]);
        assert!(report.blocked);
        assert!(codes(&report).contains(&"UndeclaredMint"));
    }

    #[test]
    fn an_undeclared_token_debit_is_critical() {
        let before_bytes = token_account_bytes(&[1u8; 32], &[2u8; 32], 1_000, None, 1, None);
        let after_bytes = token_account_bytes(&[1u8; 32], &[2u8; 32], 0, None, 1, None);
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: ALICE.to_string(),
                before: Some(token_snapshot(ALICE, 2_039_280, &before_bytes)),
                after: Some(token_snapshot(ALICE, 2_039_280, &after_bytes)),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            // No artifact was simulated in this fixture, so there is no
            // measured effect count to compare coverage against.
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(ALICE, true)];
        // "Update the metadata URI" promises no value movement at all.
        let report = check(
            &diff,
            &accounts,
            &["initialize the metadata account".to_string()],
        );
        assert!(report.blocked);
        assert!(codes(&report).contains(&"UndeclaredTokenDebit"));
    }

    /// A token debit of `owner_key`'s account `ALICE`, as one delta.
    fn token_debit_of(owner_key: &[u8; 32]) -> StateDiff {
        let before = token_account_bytes(&[1u8; 32], owner_key, 1_000, None, 1, None);
        let after = token_account_bytes(&[1u8; 32], owner_key, 0, None, 1, None);
        StateDiff {
            deltas: vec![AccountDelta {
                pubkey: ALICE.to_string(),
                before: Some(token_snapshot(ALICE, 2_039_280, &before)),
                after: Some(token_snapshot(ALICE, 2_039_280, &after)),
            }],
            provenance: DiffProvenance::RpcSimulated,
            ..Default::default()
        }
    }

    /// F1 (review of the 2026-09-29 audit's fix): a declaration made only of
    /// account-name lists, or that says "no state changes", is interpretable
    /// and declares nothing, so an undeclared token debit under it is
    /// Critical, not a warning.
    #[test]
    fn a_name_list_alone_declares_nothing_and_a_debit_under_it_is_critical() {
        let diff = token_debit_of(&[2u8; 32]);
        let accounts = [account(ALICE, true)];
        for declaration in [
            vec!["modifies writable accounts: market, openOrdersAccount, owner".to_string()],
            vec!["no state changes; the memo is recorded in the transaction log".to_string()],
        ] {
            let report = check(&diff, &accounts, &declaration);
            assert!(report.blocked, "{declaration:?}: {:?}", report.findings);
            assert!(
                codes(&report).contains(&"UndeclaredTokenDebit"),
                "{declaration:?}"
            );
        }
        // Real prose Graphite cannot map still warns rather than blocks.
        let report = check(
            &diff,
            &accounts,
            &["reconciles the perpetual funding ledger".to_string()],
        );
        assert!(!report.blocked, "{:?}", report.findings);
        assert!(codes(&report).contains(&"UninterpretableDeclarationWithTokenDebit"));
    }

    /// F2: a debit declared about named accounts excuses those accounts, not
    /// a signer's other token account. A program-owned account (a pool vault)
    /// keeps the transaction-wide judgement.
    #[test]
    fn a_named_debit_does_not_excuse_draining_a_signers_other_account() {
        let signer_key = [2u8; 32];
        let signer = bs58::encode(signer_key).into_string();
        let mut diff = token_debit_of(&signer_key);
        diff.transaction_privileges = Some(TransactionPrivileges {
            signers: [signer.clone()].into(),
            writable: [signer.clone(), ALICE.to_string()].into(),
        });
        let accounts = [account(ALICE, true)];
        let declaration = ["debits accounts.vault by data.amount".to_string()];
        let report = check(&diff, &accounts, &declaration);
        assert!(report.blocked, "{:?}", report.findings);
        assert!(codes(&report).contains(&"UndeclaredTokenDebit"));

        // The same debit, declared for this account by name, is fine.
        let named = ResolvedAccount {
            name: "vault".to_string(),
            ..account(ALICE, true)
        };
        let report = check(&diff, &[named], &declaration);
        assert!(
            !codes(&report).contains(&"UndeclaredTokenDebit"),
            "{:?}",
            report.findings
        );

        // A program-owned account (no signer owns it) debited under a named
        // declaration: a pool paying out, judged as before.
        let pool_owned = token_debit_of(&[9u8; 32]);
        let mut pool_owned = pool_owned;
        pool_owned.transaction_privileges = diff.transaction_privileges.clone();
        let report = check(&pool_owned, &accounts, &declaration);
        assert!(
            !codes(&report).contains(&"UndeclaredTokenDebit"),
            "{:?}",
            report.findings
        );
    }

    /// F7: "creator" is a role, not creation.
    #[test]
    fn creator_does_not_declare_creation() {
        let e = DeclaredEffects::parse(&["marks the creator as verified".to_string()]);
        assert!(!e.create);
        let e = DeclaredEffects::parse(&["creates accounts.metadata".to_string()]);
        assert!(e.create);
    }

    #[test]
    fn an_undeclared_closure_is_critical() {
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: BOB.to_string(),
                before: Some(lamport_snapshot(BOB, 2_039_280)),
                after: Some(lamport_snapshot(BOB, 0)),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            // No artifact was simulated in this fixture, so there is no
            // measured effect count to compare coverage against.
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(BOB, true)];
        let report = check(
            &diff,
            &accounts,
            &["initialize the metadata account".to_string()],
        );
        assert!(report.blocked);
        assert!(codes(&report).contains(&"UndeclaredAccountClosure"));
    }

    #[test]
    fn a_declared_closure_is_clean() {
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: BOB.to_string(),
                before: Some(lamport_snapshot(BOB, 2_039_280)),
                after: Some(lamport_snapshot(BOB, 0)),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            // No artifact was simulated in this fixture, so there is no
            // measured effect count to compare coverage against.
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(BOB, true)];
        let report = check(
            &diff,
            &accounts,
            &["close the token account and return rent".to_string()],
        );
        assert!(report.findings.is_empty(), "got {:?}", report.findings);
    }

    // ── Boundaries and false-positive guards ────────────────────────────────

    #[test]
    fn the_fee_payers_fee_sized_outflow_is_not_reported_as_a_debit() {
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: ALICE.to_string(),
                before: Some(lamport_snapshot(ALICE, 10_000)),
                after: Some(lamport_snapshot(ALICE, 9_995)),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 5,
            covers_all_writable: false,
            // No artifact was simulated in this fixture, so there is no
            // measured effect count to compare coverage against.
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(ALICE, true)];
        let report = check(
            &diff,
            &accounts,
            &["initialize the metadata account".to_string()],
        );
        assert!(
            report.findings.is_empty(),
            "paying the fee is not a debit, got {:?}",
            report.findings
        );
    }

    #[test]
    fn a_silent_manifest_cannot_be_contradicted_about_value() {
        // No prose means no promise. Raising an "undeclared" finding against a
        // manifest that declared nothing would fire on every instruction whose
        // state changes were never written down.
        let before_bytes = token_account_bytes(&[1u8; 32], &[2u8; 32], 1_000, None, 1, None);
        let after_bytes = token_account_bytes(&[1u8; 32], &[2u8; 32], 500, None, 1, None);
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: ALICE.to_string(),
                before: Some(token_snapshot(ALICE, 2_039_280, &before_bytes)),
                after: Some(token_snapshot(ALICE, 2_039_280, &after_bytes)),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            // No artifact was simulated in this fixture, so there is no
            // measured effect count to compare coverage against.
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(ALICE, true)];
        let report = check(&diff, &accounts, &[]);
        assert!(report.findings.is_empty(), "got {:?}", report.findings);
    }

    #[test]
    fn a_silent_manifest_is_still_held_to_the_structural_rules() {
        // Value movement needs prose to contradict. Handing an account to a
        // new owner does not — nothing about a silent manifest makes a
        // takeover acceptable.
        let mut after = lamport_snapshot(ALICE, 10_000);
        after.owner = ATTACKER.to_string();
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: ALICE.to_string(),
                before: Some(lamport_snapshot(ALICE, 10_000)),
                after: Some(after),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            // No artifact was simulated in this fixture, so there is no
            // measured effect count to compare coverage against.
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(ALICE, true)];
        let report = check(&diff, &accounts, &[]);
        assert!(report.blocked, "got {:?}", report.findings);
        assert!(codes(&report).contains(&"UndeclaredOwnerReassignment"));
    }

    #[test]
    fn a_write_to_a_readonly_account_is_critical_only_when_privileges_are_grounded() {
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: BOB.to_string(),
                before: Some(lamport_snapshot(BOB, 100)),
                after: Some(lamport_snapshot(BOB, 200)),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            // No artifact was simulated in this fixture, so there is no
            // measured effect count to compare coverage against.
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(BOB, false)];
        let declared = ["credit destination".to_string()];

        let grounded = check_state_diff(&StateDiffCheck {
            diff: &diff,
            resolved_accounts: &accounts,
            privileges_grounded: true,
            expected_state_changes: &declared,
            fee_payer: Some(ALICE),
        });
        assert!(grounded.blocked);
        assert!(codes(&grounded).contains(&"WriteToReadonlyAccount"));

        let ungrounded = check_state_diff(&StateDiffCheck {
            diff: &diff,
            resolved_accounts: &accounts,
            privileges_grounded: false,
            expected_state_changes: &declared,
            fee_payer: Some(ALICE),
        });
        assert!(
            !ungrounded.blocked,
            "unverified AccountMeta data must not block (P12)"
        );
        assert!(codes(&ungrounded).contains(&"WriteToUndeclaredWritableAccount"));
    }

    #[test]
    fn an_empty_diff_against_a_declaring_manifest_warns_but_does_not_block() {
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: ALICE.to_string(),
                before: Some(lamport_snapshot(ALICE, 10_000)),
                after: Some(lamport_snapshot(ALICE, 10_000)),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            // No artifact was simulated in this fixture, so there is no
            // measured effect count to compare coverage against.
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(ALICE, true)];
        let report = check(&diff, &accounts, &["debit source".to_string()]);
        assert!(report.empty);
        assert!(!report.blocked);
        assert!(codes(&report).contains(&"NoObservedStateChange"));
    }

    #[test]
    fn account_creation_debits_the_payer_without_a_finding() {
        // Rent leaves the payer and lands in the new account. A "create"
        // declaration covers it; reporting an outflow here would fire on every
        // ATA creation on Solana.
        let diff = StateDiff {
            deltas: vec![
                AccountDelta {
                    pubkey: ALICE.to_string(),
                    before: Some(lamport_snapshot(ALICE, 10_000_000)),
                    after: Some(lamport_snapshot(ALICE, 7_955_720)),
                },
                AccountDelta {
                    pubkey: BOB.to_string(),
                    before: None,
                    after: Some(lamport_snapshot(BOB, 2_039_280)),
                },
            ],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 5_000,
            covers_all_writable: true,
            // No artifact was simulated in this fixture, so there is no
            // measured effect count to compare coverage against.
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(ALICE, true), account(BOB, true)];
        let report = check(
            &diff,
            &accounts,
            &["create the associated token account".to_string()],
        );
        assert!(report.findings.is_empty(), "got {:?}", report.findings);
    }

    #[test]
    fn an_absent_declaration_is_not_the_same_as_an_uninterpretable_one() {
        // These two states drive different severities, so conflating them is
        // the difference between silently allowing a drain and blocking a
        // protocol for its choice of words.
        let absent = DeclaredEffects::parse(&[]);
        assert!(absent.is_silent());
        assert!(!absent.is_interpretable());

        let unknown = DeclaredEffects::parse(&["frobnicate the widget".to_string()]);
        assert!(!unknown.is_silent(), "prose exists, so nothing is absent");
        assert!(!unknown.is_interpretable());
        assert!(unknown.unrecognised);

        let known = DeclaredEffects::parse(&["debit the source account".to_string()]);
        assert!(known.is_interpretable());
        assert!(known.debit);
    }

    #[test]
    fn a_token_debit_under_uninterpretable_prose_warns_instead_of_blocking() {
        // The manifest is describing something; Graphite just cannot map it.
        // Blocking here would punish a protocol for its wording (P12), but
        // staying silent would hide a real balance drop.
        let before_bytes = token_account_bytes(&[1u8; 32], &[2u8; 32], 1_000, None, 1, None);
        let after_bytes = token_account_bytes(&[1u8; 32], &[2u8; 32], 0, None, 1, None);
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: ALICE.to_string(),
                before: Some(token_snapshot(ALICE, 2_039_280, &before_bytes)),
                after: Some(token_snapshot(ALICE, 2_039_280, &after_bytes)),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            // No artifact was simulated in this fixture, so there is no
            // measured effect count to compare coverage against.
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(ALICE, true)];
        let report = check(&diff, &accounts, &["frobnicate the widget".to_string()]);
        assert!(!report.blocked, "got {:?}", report.findings);
        assert!(codes(&report).contains(&"UninterpretableDeclarationWithTokenDebit"));
    }

    #[test]
    fn an_undeclared_creation_is_flagged_when_the_manifest_declares_other_effects() {
        // The account did not exist; the manifest talks about transferring,
        // not creating. Something else got built during the transfer.
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: BOB.to_string(),
                before: None,
                after: Some(AccountSnapshot {
                    pubkey: BOB.to_string(),
                    lamports: 2_039_280,
                    owner: ATTACKER.to_string(),
                    data_len: 165,
                    token: None,
                    mint: None,
                    extensions: Default::default(),
                    transfer_fee_withheld: None,
                    transfer_fee_config: None,
                    token2022_powers: None,
                    data_sha256: None,
                    executable: false,
                    native_authorities: Vec::new(),
                }),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            // No artifact was simulated in this fixture, so there is no
            // measured effect count to compare coverage against.
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(BOB, true)];
        // `before: None` means owner_change() cannot fire — there is no prior
        // owner to compare against — so the creation itself has to be what
        // makes this visible.
        let report = check(&diff, &accounts, &["transfer tokens".to_string()]);
        assert!(codes(&report).contains(&"UndeclaredAccountCreation"));
        assert!(
            !report.blocked,
            "creating an account is not on its own a loss; the rent outflow is what blocks"
        );
    }

    #[test]
    fn every_finding_carries_a_nonempty_code_and_detail() {
        // Findings are the layer's entire explanation (P3). A blank one would
        // block a transaction with no way for the operator to learn why.
        let mut after = lamport_snapshot(ALICE, 0);
        after.owner = ATTACKER.to_string();
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: ALICE.to_string(),
                before: Some(lamport_snapshot(ALICE, 10_000)),
                after: Some(after),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            // No artifact was simulated in this fixture, so there is no
            // measured effect count to compare coverage against.
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let accounts = [account(ALICE, true)];
        let report = check(
            &diff,
            &accounts,
            &["initialize the metadata account".to_string()],
        );
        assert!(!report.findings.is_empty());
        for f in &report.findings {
            assert!(!f.code.is_empty(), "empty code in {f:?}");
            assert!(!f.detail.is_empty(), "empty detail in {f:?}");
        }
    }
}

/// W19 (external review, verified 2026-10-03): what a declaration line says
/// about each account it names.
#[cfg(test)]
mod w19_scope_tests {
    use super::*;
    use crate::account_resolution::{AccountIdentity, ResolvedAccount};

    const SOURCE: &str = "A1ice11111111111111111111111111111111111111";
    const DEST: &str = "B0b11111111111111111111111111111111111111111";
    const WALLET: &str = "Wa11et1111111111111111111111111111111111111";

    fn named(address: &str, name: &str, signer: bool) -> ResolvedAccount {
        ResolvedAccount {
            address: address.to_string(),
            role: "account".to_string(),
            name: name.to_string(),
            is_pda: false,
            is_signer: signer,
            is_writable: true,
            pda_seeds: vec![],
            identity: AccountIdentity::Unverified,
            expected_address_mismatch: false,
            pda_mismatch: false,
            privilege_mismatch: false,
        }
    }

    fn token_account(delegate: Option<[u8; 32]>) -> Vec<u8> {
        let mut d = vec![0u8; TOKEN_ACCOUNT_LEN];
        d[32..64].copy_from_slice(&[9u8; 32]);
        d[64..72].copy_from_slice(&1_000u64.to_le_bytes());
        if let Some(k) = delegate {
            d[72..76].copy_from_slice(&1u32.to_le_bytes());
            d[76..108].copy_from_slice(&k);
            d[121..129].copy_from_slice(&1_000u64.to_le_bytes());
        }
        d[108] = 1;
        d
    }

    fn report(
        deltas: Vec<AccountDelta>,
        accounts: &[ResolvedAccount],
        declared: &[&str],
    ) -> StateDiffReport {
        report_with(deltas, accounts, declared, L4Relaxations::default())
    }

    fn report_with(
        deltas: Vec<AccountDelta>,
        accounts: &[ResolvedAccount],
        declared: &[&str],
        relax: L4Relaxations,
    ) -> StateDiffReport {
        let diff = StateDiff {
            deltas,
            provenance: DiffProvenance::RpcSimulated,
            ..Default::default()
        };
        let declared: Vec<String> = declared.iter().map(|s| s.to_string()).collect();
        check_state_diff_with(
            &StateDiffCheck {
                diff: &diff,
                resolved_accounts: accounts,
                privileges_grounded: true,
                expected_state_changes: &declared,
                fee_payer: None,
            },
            relax,
        )
    }

    fn codes(r: &StateDiffReport) -> Vec<&str> {
        r.findings.iter().map(|f| f.code.as_str()).collect()
    }

    /// Revoke's own prose ("revokes accounts.source delegated_amount") used to
    /// declare a delegation on source, and so excused a delegate granted
    /// there by a CPI.
    #[test]
    fn a_revoke_declares_no_delegate_grant() {
        let delta = AccountDelta {
            pubkey: SOURCE.to_string(),
            before: Some(AccountSnapshot::from_raw(
                SOURCE,
                2_039_280,
                SPL_TOKEN_PROGRAM,
                &token_account(None),
            )),
            after: Some(AccountSnapshot::from_raw(
                SOURCE,
                2_039_280,
                SPL_TOKEN_PROGRAM,
                &token_account(Some([66u8; 32])),
            )),
        };
        let r = report(
            vec![delta],
            &[named(SOURCE, "source", false)],
            &["revokes accounts.source delegated_amount (sets to 0)"],
        );
        assert!(
            codes(&r).contains(&"UndeclaredDelegateGrant"),
            "{:?}",
            r.findings
        );
        assert!(r.blocked);
    }

    /// CloseAccount's prose names the destination as where the lamports go.
    /// That excused a closure of the destination — usually the user's wallet.
    #[test]
    fn where_lamports_go_is_not_what_is_closed() {
        let lamports = |k: &str, n: u64| AccountSnapshot::from_raw(k, n, SYSTEM_PROGRAM, &[]);
        let declared =
            ["closes accounts.account and transfers its lamports to accounts.destination"];
        let closing = |who: &str| AccountDelta {
            pubkey: who.to_string(),
            before: Some(lamports(who, 5_000_000)),
            after: Some(lamports(who, 0)),
        };
        let accounts = [
            named(SOURCE, "account", false),
            named(DEST, "destination", false),
        ];
        let r = report(vec![closing(DEST)], &accounts, &declared);
        assert!(
            codes(&r).contains(&"UndeclaredAccountClosure"),
            "{:?}",
            r.findings
        );
        let r = report(vec![closing(SOURCE)], &accounts, &declared);
        assert!(
            !codes(&r).contains(&"UndeclaredAccountClosure"),
            "{:?}",
            r.findings
        );
    }

    const SCOPED_DEBIT: &[&str] =
        &["transfers data.amount tokens from accounts.source to accounts.destination"];

    fn wallet_spends(lamports: u64) -> AccountDelta {
        AccountDelta {
            pubkey: WALLET.to_string(),
            before: Some(AccountSnapshot::from_raw(
                WALLET,
                10_000_000_000,
                SYSTEM_PROGRAM,
                &[],
            )),
            after: Some(AccountSnapshot::from_raw(
                WALLET,
                10_000_000_000 - lamports,
                SYSTEM_PROGRAM,
                &[],
            )),
        }
    }

    fn w19_accounts() -> [ResolvedAccount; 2] {
        [
            named(SOURCE, "source", false),
            named(WALLET, "authority", true),
        ]
    }

    /// A debit declared about a token account says nothing about the signer's
    /// wallet. Round 32: refused by default (it was a warning since W19).
    #[test]
    fn lamports_leaving_the_signers_wallet_outside_the_declared_debit_are_critical() {
        let r = report(
            vec![wallet_spends(5_000_000_000)],
            &w19_accounts(),
            SCOPED_DEBIT,
        );
        let f = r
            .findings
            .iter()
            .find(|f| f.code == "SignerLamportsOutsideDeclaredDebit")
            .unwrap_or_else(|| panic!("{:?}", r.findings));
        assert_eq!(f.severity, DiffSeverity::Critical);
        assert!(f.detail.contains("5000000000"), "{}", f.detail);
        assert!(r.blocked, "{:?}", r.findings);
    }

    /// The operator's opt-out restores the W19 warning, and only that.
    #[test]
    fn the_operator_may_restore_the_w19_warning() {
        let relax = L4Relaxations {
            signer_lamports_outside_declared_debit: true,
            ..Default::default()
        };
        let r = report_with(
            vec![wallet_spends(5_000_000_000)],
            &w19_accounts(),
            SCOPED_DEBIT,
            relax,
        );
        let f = r
            .findings
            .iter()
            .find(|f| f.code == "SignerLamportsOutsideDeclaredDebit")
            .unwrap_or_else(|| panic!("{:?}", r.findings));
        assert_eq!(f.severity, DiffSeverity::Warning);
        assert!(!r.blocked, "{:?}", r.findings);
    }

    /// Control: what the signer's lamports bought that stays the signer's —
    /// the rent of an account the transaction creates, SOL wrapped into the
    /// signer's own token account — is not a loss, under the new default.
    ///
    /// Round 34 (R33-6) re-pin: the created token account used to be owned
    /// by a key that does not sign (`token_account(None)` holds `[9; 32]`),
    /// and its rent passed as the signer's own under the old rule that
    /// credited the rent of ANY created account. That owner can close the
    /// account and keep the rent, so it is a loss now (asserted below); the
    /// control's created account is the signer's own.
    #[test]
    fn rent_for_a_created_account_and_wrapped_sol_are_not_a_w19_loss() {
        let created = "Crea7ed111111111111111111111111111111111111";
        let rent = u64::try_from(rent_exempt_minimum(TOKEN_ACCOUNT_LEN)).unwrap();
        let mut owned_by_wallet = token_account(None);
        owned_by_wallet[32..64].copy_from_slice(
            crate::solana_types::Pubkey::from_base58(WALLET)
                .unwrap()
                .as_bytes(),
        );
        let pays_rent = |data: &[u8]| AccountDelta {
            pubkey: created.to_string(),
            before: None,
            after: Some(AccountSnapshot::from_raw(
                created,
                rent,
                SPL_TOKEN_PROGRAM,
                data,
            )),
        };
        let r = report(
            vec![wallet_spends(rent), pays_rent(&owned_by_wallet)],
            &w19_accounts(),
            SCOPED_DEBIT,
        );
        assert!(
            !codes(&r).contains(&"SignerLamportsOutsideDeclaredDebit"),
            "{:?}",
            r.findings
        );
        // The same rent into a token account somebody else owns.
        let r = report(
            vec![wallet_spends(rent), pays_rent(&token_account(None))],
            &w19_accounts(),
            SCOPED_DEBIT,
        );
        assert!(
            codes(&r).contains(&"SignerLamportsOutsideDeclaredDebit"),
            "{:?}",
            r.findings
        );

        // Wrapping: lamports arrive in a token account the signer owns.
        let wsol = "WSo1111111111111111111111111111111111111111";
        let wraps = AccountDelta {
            pubkey: wsol.to_string(),
            before: Some(AccountSnapshot::from_raw(
                wsol,
                2_039_280,
                SPL_TOKEN_PROGRAM,
                &owned_by_wallet,
            )),
            after: Some(AccountSnapshot::from_raw(
                wsol,
                2_039_280 + 1_000_000,
                SPL_TOKEN_PROGRAM,
                &owned_by_wallet,
            )),
        };
        let r = report(
            vec![wallet_spends(1_000_000), wraps],
            &w19_accounts(),
            SCOPED_DEBIT,
        );
        assert!(
            !codes(&r).contains(&"SignerLamportsOutsideDeclaredDebit"),
            "{:?}",
            r.findings
        );

        // What is left over beyond the rent is still the signer's loss.
        let r = report(
            vec![wallet_spends(rent + 7_000_000), pays_rent(&owned_by_wallet)],
            &w19_accounts(),
            SCOPED_DEBIT,
        );
        let f = r
            .findings
            .iter()
            .find(|f| f.code == "SignerLamportsOutsideDeclaredDebit")
            .unwrap_or_else(|| panic!("{:?}", r.findings));
        assert!(f.detail.starts_with("7000000 "), "{}", f.detail);
        assert_eq!(f.severity, DiffSeverity::Critical);
    }

    // ── Round 34: the Round 33 audit's L4 findings, at the layer ───────────

    const ATTACKER: &str = "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7";
    const POOL: &str = "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx";
    const UNSCOPED: &[&str] = &["transfers funds between the protocol and the involved accounts"];

    fn system(who: &str, before: u64, after: u64) -> AccountDelta {
        AccountDelta {
            pubkey: who.to_string(),
            before: (before > 0)
                .then(|| AccountSnapshot::from_raw(who, before, SYSTEM_PROGRAM, &[])),
            after: Some(AccountSnapshot::from_raw(who, after, SYSTEM_PROGRAM, &[])),
        }
    }

    fn token_of(owner: &str, amount: u64) -> Vec<u8> {
        let mut d = token_account(None);
        d[32..64].copy_from_slice(
            crate::solana_types::Pubkey::from_base58(owner)
                .unwrap()
                .as_bytes(),
        );
        d[64..72].copy_from_slice(&amount.to_le_bytes());
        d
    }

    fn finding<'a>(r: &'a StateDiffReport, code: &str) -> &'a StateDiffFinding {
        r.findings
            .iter()
            .find(|f| f.code == code)
            .unwrap_or_else(|| panic!("no {code} in {:?}", r.findings))
    }

    /// R33-5: the signer's wallet −5 SOL, a stranger +5 SOL, under a
    /// declaration whose only debit line names no account. That line used to
    /// excuse every account's loss — W19 never fired, nor the no-debit rule.
    #[test]
    fn a_signers_loss_under_a_debit_line_naming_no_account_is_refused() {
        let r = report(
            vec![
                system(WALLET, 10_000_000_000, 5_000_000_000),
                system(ATTACKER, 1, 5_000_000_001),
            ],
            &w19_accounts(),
            UNSCOPED,
        );
        let f = finding(&r, "SignerLamportsUnderUnscopedDebit");
        assert_eq!(f.severity, DiffSeverity::Critical);
        assert!(f.detail.starts_with("5000000000 "), "{}", f.detail);
        assert!(r.blocked);
    }

    /// R33-5, tokens: a token account the signer owns debited under the same
    /// line.
    #[test]
    fn a_signers_token_debit_under_a_debit_line_naming_no_account_is_refused() {
        let user = AccountDelta {
            pubkey: SOURCE.to_string(),
            before: Some(AccountSnapshot::from_raw(
                SOURCE,
                2_039_280,
                SPL_TOKEN_PROGRAM,
                &token_of(WALLET, 1_000),
            )),
            after: Some(AccountSnapshot::from_raw(
                SOURCE,
                2_039_280,
                SPL_TOKEN_PROGRAM,
                &token_of(WALLET, 0),
            )),
        };
        let r = report(vec![user], &w19_accounts(), UNSCOPED);
        let f = finding(&r, "SignerTokenDebitUnderUnscopedDebit");
        assert_eq!(f.severity, DiffSeverity::Critical);
        assert_eq!(f.account.as_deref(), Some(SOURCE));
    }

    /// The pool side keeps "anywhere": a vault no signer owns paying out
    /// under the same line is the line's, and raises nothing.
    #[test]
    fn a_vault_paying_out_under_a_debit_line_naming_no_account_is_not_a_signer_finding() {
        let vault = AccountDelta {
            pubkey: DEST.to_string(),
            before: Some(AccountSnapshot::from_raw(
                DEST,
                2_039_280,
                SPL_TOKEN_PROGRAM,
                &token_of(POOL, 1_000),
            )),
            after: Some(AccountSnapshot::from_raw(
                DEST,
                2_039_280,
                SPL_TOKEN_PROGRAM,
                &token_of(POOL, 400),
            )),
        };
        let accounts = [
            named(DEST, "vault", false),
            named(WALLET, "authority", true),
        ];
        let r = report(vec![vault], &accounts, UNSCOPED);
        assert!(!r.blocked, "{:?}", r.findings);
    }

    /// The Round 30/32 opt-out for declarations Graphite cannot read covers
    /// this one, for a class that moves value — and only then.
    #[test]
    fn the_unreadable_declaration_opt_out_relaxes_an_unscoped_debit_for_a_value_class() {
        let relax = L4Relaxations {
            unreadable_value_declarations: true,
            ..Default::default()
        };
        let deltas = || {
            vec![
                system(WALLET, 10_000_000_000, 5_000_000_000),
                system(ATTACKER, 1, 5_000_000_001),
            ]
        };
        let withdraw: Vec<String> = UNSCOPED
            .iter()
            .map(|s| s.to_string())
            .chain([security_class_line("withdraw")])
            .collect();
        let withdraw: Vec<&str> = withdraw.iter().map(String::as_str).collect();
        let with_recipient = [
            named(WALLET, "authority", true),
            named(ATTACKER, "recipient", false),
        ];
        let r = report_with(deltas(), &with_recipient, &withdraw, relax);
        assert_eq!(
            finding(&r, "SignerLamportsUnderUnscopedDebit").severity,
            DiffSeverity::Warning
        );
        assert!(!r.blocked, "{:?}", r.findings);
        let inert: Vec<String> = UNSCOPED
            .iter()
            .map(|s| s.to_string())
            .chain([security_class_line("inert")])
            .collect();
        let inert: Vec<&str> = inert.iter().map(String::as_str).collect();
        let r = report_with(deltas(), &with_recipient, &inert, relax);
        assert_eq!(
            finding(&r, "SignerLamportsUnderUnscopedDebit").severity,
            DiffSeverity::Critical
        );
        // The W19 opt-out does not reach it.
        let r = report_with(
            deltas(),
            &with_recipient,
            &withdraw,
            L4Relaxations {
                signer_lamports_outside_declared_debit: true,
                ..Default::default()
            },
        );
        assert!(r.blocked, "{:?}", r.findings);
    }

    /// R33-6: the wallet pays 7.30 SOL into a new 1 MiB account another
    /// program owns, under a scoped token-debit declaration. Its rent is not
    /// the signer's: W19 names all of it.
    #[test]
    fn rent_paid_into_a_created_account_another_program_owns_is_a_w19_loss() {
        let created = "Crea7ed111111111111111111111111111111111111";
        let rent = u64::try_from(rent_exempt_minimum(1 << 20)).unwrap();
        let foreign = AccountDelta {
            pubkey: created.to_string(),
            before: None,
            after: Some(AccountSnapshot::from_raw(
                created,
                rent,
                ATTACKER,
                &vec![0u8; 1 << 20],
            )),
        };
        let r = report(
            vec![wallet_spends(rent), foreign],
            &w19_accounts(),
            SCOPED_DEBIT,
        );
        let f = finding(&r, "SignerLamportsOutsideDeclaredDebit");
        assert!(f.detail.starts_with(&format!("{rent} ")), "{}", f.detail);
        assert_eq!(f.severity, DiffSeverity::Critical);
    }

    /// R33-6, no debit declared: the same rent is `UndeclaredSignerLamportDebit`;
    /// the rent of an account the declaration NAMES as created, owned by
    /// the instruction's own program, is the signer's cost.
    #[test]
    fn rent_is_a_signers_cost_only_for_an_account_the_declaration_names_and_its_program_owns() {
        let created = "Crea7ed111111111111111111111111111111111111";
        let program = "Prog111111111111111111111111111111111111111";
        let rent = u64::try_from(rent_exempt_minimum(1 << 20)).unwrap();
        let made = |owner: &str| AccountDelta {
            pubkey: created.to_string(),
            before: None,
            after: Some(AccountSnapshot::from_raw(
                created,
                rent,
                owner,
                &vec![0u8; 1 << 20],
            )),
        };
        let accounts = [
            named(created, "position", false),
            named(WALLET, "payer", true),
        ];
        let declared = [
            "creates accounts.position".to_string(),
            instruction_program_line(program),
        ];
        let declared: Vec<&str> = declared.iter().map(String::as_str).collect();
        // Another program owns it.
        let r = report(
            vec![wallet_spends(rent), made(ATTACKER)],
            &accounts,
            &declared,
        );
        let f = finding(&r, "UndeclaredSignerLamportDebit");
        assert!(f.detail.contains(&rent.to_string()), "{}", f.detail);
        // The instruction's own program owns it.
        let r = report(
            vec![wallet_spends(rent), made(program)],
            &accounts,
            &declared,
        );
        assert!(
            !codes(&r).contains(&"UndeclaredSignerLamportDebit"),
            "{:?}",
            r.findings
        );
        // Owned by the program, but the declaration does not name it.
        let r = report(
            vec![wallet_spends(rent), made(program)],
            &accounts,
            &[
                "creates a new account".to_string(),
                instruction_program_line(program),
            ]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        );
        assert!(
            codes(&r).contains(&"UndeclaredSignerLamportDebit"),
            "{:?}",
            r.findings
        );
    }

    /// R33-7: a co-signer's gain does not offset the user's loss — a fresh
    /// co-signer another program owns, and an existing relayer wallet.
    #[test]
    fn a_cosigners_gain_does_not_offset_the_users_loss() {
        let cosigner = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
        let accounts = [
            named(WALLET, "payer", true),
            named(cosigner, "relayer", true),
            named(SOURCE, "mint", false),
        ];
        let declared = &["creates accounts.mint"];
        // (a) fresh, handed to another program.
        let fresh = AccountDelta {
            pubkey: cosigner.to_string(),
            before: None,
            after: Some(AccountSnapshot::from_raw(
                cosigner,
                5_000_000_000,
                ATTACKER,
                &[],
            )),
        };
        let r = report(
            vec![wallet_spends(5_000_000_000), fresh],
            &accounts,
            declared,
        );
        let f = finding(&r, "UndeclaredSignerLamportDebit");
        assert!(f.detail.contains("5000000000"), "{}", f.detail);
        // (b) an existing wallet.
        let r = report(
            vec![
                wallet_spends(5_000_000_000),
                system(cosigner, 1_000_000_000, 6_000_000_000),
            ],
            &accounts,
            declared,
        );
        let f = finding(&r, "UndeclaredSignerLamportDebit");
        assert!(f.detail.contains("5000000000"), "{}", f.detail);
        // Control: each moves nothing.
        let r = report(
            vec![system(cosigner, 1_000_000_000, 1_000_000_000)],
            &accounts,
            declared,
        );
        assert!(
            !codes(&r).contains(&"UndeclaredSignerLamportDebit"),
            "{:?}",
            r.findings
        );
    }

    /// R33-7: wrapped SOL counts toward the signer that holds it only.
    #[test]
    fn sol_wrapped_into_another_signers_account_is_not_the_payers() {
        let cosigner = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
        let wsol = "WSo1111111111111111111111111111111111111111";
        let held = |amount: u64| {
            AccountSnapshot::from_raw(
                wsol,
                2_039_280 + amount,
                SPL_TOKEN_PROGRAM,
                &token_of(cosigner, amount),
            )
        };
        let wraps = AccountDelta {
            pubkey: wsol.to_string(),
            before: Some(held(0)),
            after: Some(held(1_000_000_000)),
        };
        let accounts = [
            named(SOURCE, "source", false),
            named(WALLET, "authority", true),
            named(cosigner, "relayer", true),
        ];
        let r = report(
            vec![wallet_spends(1_000_000_000), wraps],
            &accounts,
            SCOPED_DEBIT,
        );
        let f = finding(&r, "SignerLamportsOutsideDeclaredDebit");
        assert!(f.detail.starts_with("1000000000 "), "{}", f.detail);
    }

    /// R33-10: a pool's 1 SOL wSOL payout into the user's account is not the
    /// user's own SOL changing form, and does not offset 1 SOL sent from the
    /// user's wallet to someone else. (The wrap itself stays credited:
    /// `rent_for_a_created_account_and_wrapped_sol_are_not_a_w19_loss`.)
    #[test]
    fn a_vaults_payout_into_the_signers_account_does_not_offset_a_wallet_drain() {
        let wsol = "WSo1111111111111111111111111111111111111111";
        let vault = "Vau1t11111111111111111111111111111111111111";
        let snap = |key: &str, owner: &str, amount: u64| {
            AccountSnapshot::from_raw(
                key,
                2_039_280 + amount,
                SPL_TOKEN_PROGRAM,
                &token_of(owner, amount),
            )
        };
        let payout = AccountDelta {
            pubkey: wsol.to_string(),
            before: Some(snap(wsol, WALLET, 0)),
            after: Some(snap(wsol, WALLET, 1_000_000_000)),
        };
        let pays = AccountDelta {
            pubkey: vault.to_string(),
            before: Some(snap(vault, POOL, 5_000_000_000)),
            after: Some(snap(vault, POOL, 4_000_000_000)),
        };
        let r = report(
            vec![
                wallet_spends(1_000_000_000),
                system(ATTACKER, 1, 1_000_000_001),
                payout,
                pays,
            ],
            &w19_accounts(),
            SCOPED_DEBIT,
        );
        let f = finding(&r, "SignerLamportsOutsideDeclaredDebit");
        assert!(f.detail.starts_with("1000000000 "), "{}", f.detail);
    }

    /// R33-14, at the layer: a nonce account created with an authority no
    /// signer holds; and a stake account split off one the signer stakes,
    /// carrying its authorities, introduces no one.
    #[test]
    fn a_created_native_accounts_authorities_must_sign() {
        let nonce_key = "Nonce11111111111111111111111111111111111111";
        let mut nonce = vec![0u8; 80];
        nonce[4..8].copy_from_slice(&1u32.to_le_bytes());
        nonce[8..40].copy_from_slice(
            crate::solana_types::Pubkey::from_base58(ATTACKER)
                .unwrap()
                .as_bytes(),
        );
        let created = AccountDelta {
            pubkey: nonce_key.to_string(),
            before: None,
            after: Some(AccountSnapshot::from_raw(
                nonce_key,
                1_447_680,
                SYSTEM_PROGRAM,
                &nonce,
            )),
        };
        let r = report(vec![created], &w19_accounts(), SCOPED_DEBIT);
        let f = finding(&r, "CreatedAccountAuthorityNotSigner");
        assert!(
            f.detail.contains("nonce authority") && f.detail.contains(ATTACKER),
            "{}",
            f.detail
        );
        assert_eq!(f.severity, DiffSeverity::Critical);

        // A split: the source's staker signs; the new account carries its
        // (cold) withdrawer, which does not sign.
        let pk = |s: &str| {
            *crate::solana_types::Pubkey::from_base58(s)
                .unwrap()
                .as_bytes()
        };
        let stake = |staker: &str, withdrawer: &str| {
            let mut d = vec![0u8; 200];
            d[0..4].copy_from_slice(&1u32.to_le_bytes());
            d[12..44].copy_from_slice(&pk(staker));
            d[44..76].copy_from_slice(&pk(withdrawer));
            d
        };
        let (src, new) = (
            "SrcStake1111111111111111111111111111111111",
            "NewStake1111111111111111111111111111111111",
        );
        let split = |withdrawer: &str| {
            vec![
                AccountDelta {
                    pubkey: src.to_string(),
                    before: Some(AccountSnapshot::from_raw(
                        src,
                        10_000_000_000,
                        STAKE_PROGRAM,
                        &stake(WALLET, ATTACKER),
                    )),
                    after: Some(AccountSnapshot::from_raw(
                        src,
                        6_000_000_000,
                        STAKE_PROGRAM,
                        &stake(WALLET, ATTACKER),
                    )),
                },
                AccountDelta {
                    pubkey: new.to_string(),
                    before: Some(AccountSnapshot::from_raw(
                        new,
                        2_282_880,
                        STAKE_PROGRAM,
                        &[0u8; 200],
                    )),
                    after: Some(AccountSnapshot::from_raw(
                        new,
                        6_002_282_880,
                        STAKE_PROGRAM,
                        &stake(WALLET, withdrawer),
                    )),
                },
            ]
        };
        let declared = &[
            "debits accounts.source by data.lamports",
            "credits accounts.destination by data.lamports",
        ];
        let accounts = [
            named(src, "source", false),
            named(new, "destination", false),
            named(WALLET, "authority", true),
        ];
        let r = report(split(ATTACKER), &accounts, declared);
        assert!(
            !codes(&r).contains(&"CreatedAccountAuthorityNotSigner"),
            "{:?}",
            r.findings
        );
        // The same split handing the new account to someone else.
        let other = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
        let r = report(split(other), &accounts, declared);
        assert!(
            codes(&r).contains(&"CreatedAccountAuthorityNotSigner"),
            "{:?}",
            r.findings
        );
    }

    /// R33-15: a debit the located instruction's data states binds the
    /// wallet to that amount.
    #[test]
    fn a_stated_lamport_debit_binds_the_wallet_to_its_amount() {
        let bob = "B0b11111111111111111111111111111111111111111";
        let accounts = [named(WALLET, "from", true), named(bob, "to", false)];
        let declared = [
            "debits accounts.from by data.amount lamports".to_string(),
            "credits accounts.to by data.amount lamports".to_string(),
            lamport_amount_line(WALLET, 1_000_000),
        ];
        let declared: Vec<&str> = declared.iter().map(String::as_str).collect();
        let r = report(
            vec![
                system(WALLET, 20_000_000_000, 9_999_000_000),
                system(bob, 1, 1_000_001),
                system(ATTACKER, 1, 10_000_000_001),
            ],
            &accounts,
            &declared,
        );
        let f = finding(&r, "SignerLamportsBeyondDeclaredAmount");
        assert_eq!(f.severity, DiffSeverity::Critical);
        assert!(
            f.detail.contains("so 10000000000 lamports more"),
            "{}",
            f.detail
        );
        // Exactly the stated amount: nothing.
        let r = report(
            vec![wallet_spends(1_000_000), system(bob, 1, 1_000_001)],
            &accounts,
            &declared,
        );
        assert!(!r.blocked, "{:?}", r.findings);
    }

    /// Round 37 (R37-7, the double count): a `CreateAccount`'s stated
    /// lamports ARE what funds the account it creates, rent included. Netting
    /// that account's rent out of the wallet's loss before comparing it with
    /// the stated amount counted the rent twice, and let a sibling take one
    /// more rent's worth from the wallet unnamed.
    #[test]
    fn a_created_accounts_rent_is_not_netted_on_top_of_the_stated_amount() {
        let created = "Crea7ed111111111111111111111111111111111111";
        let program = "Prog111111111111111111111111111111111111111";
        let rent = u64::try_from(rent_exempt_minimum(1 << 10)).unwrap();
        let made = AccountDelta {
            pubkey: created.to_string(),
            before: None,
            after: Some(AccountSnapshot::from_raw(
                created,
                rent,
                program,
                &vec![0u8; 1 << 10],
            )),
        };
        // The taker is an account the transaction names (a sibling's), so
        // only the amount can tell the skim apart.
        let accounts = [
            named(WALLET, "from", true),
            named(created, "to", true),
            named(ATTACKER, "sibling", false),
        ];
        let declared = [
            "debits accounts.from by data.lamports".to_string(),
            "creates accounts.to".to_string(),
            instruction_program_line(program),
            lamport_amount_line(WALLET, rent),
        ];
        let declared: Vec<&str> = declared.iter().map(String::as_str).collect();
        // Honest: the wallet pays exactly the stated amount into the account.
        let r = report(
            vec![wallet_spends(rent), made.clone()],
            &accounts,
            &declared,
        );
        assert!(!r.blocked, "{:?}", r.findings);
        // A sibling takes one more rent's worth to someone else.
        let r = report(
            vec![wallet_spends(2 * rent), made, system(ATTACKER, 1, rent + 1)],
            &accounts,
            &declared,
        );
        let f = finding(&r, "SignerLamportsBeyondDeclaredAmount");
        assert_eq!(f.severity, DiffSeverity::Critical);
        assert!(
            f.detail.contains(&format!("so {rent} lamports more")),
            "{}",
            f.detail
        );
    }

    /// The System layouts whose data states the debit, decoded exactly.
    #[test]
    fn system_transfer_and_create_account_state_their_debit() {
        let accounts = vec![WALLET.to_string(), DEST.to_string()];
        let mut transfer = vec![2u8, 0, 0, 0];
        transfer.extend_from_slice(&7u64.to_le_bytes());
        assert_eq!(
            system_lamport_debit(SYSTEM_PROGRAM, &transfer, &accounts),
            Some((WALLET.to_string(), 7))
        );
        let mut create = vec![0u8, 0, 0, 0];
        create.extend_from_slice(&9u64.to_le_bytes());
        create.extend_from_slice(&[0u8; 40]);
        assert_eq!(
            system_lamport_debit(SYSTEM_PROGRAM, &create, &accounts),
            Some((WALLET.to_string(), 9))
        );
        transfer.push(0);
        assert_eq!(
            system_lamport_debit(SYSTEM_PROGRAM, &transfer, &accounts),
            None
        );
        assert_eq!(
            system_lamport_debit(SPL_TOKEN_PROGRAM, &create, &accounts),
            None
        );
    }
}

/// W19 (external review, verified 2026-10-03): standing powers that live in
/// account data — Token-2022 mint extension authorities and native account
/// authorities — are judged like the SPL authority fields.
#[cfg(test)]
mod w19_authority_tests {
    use super::*;
    use crate::account_resolution::{AccountIdentity, ResolvedAccount};

    const MINT: &str = "B0b11111111111111111111111111111111111111111";
    const DECLARED: &[&str] = &["debit source, credit dest"];

    fn writable(address: &str) -> ResolvedAccount {
        ResolvedAccount {
            address: address.to_string(),
            role: "account".to_string(),
            name: String::new(),
            is_pda: false,
            is_signer: false,
            is_writable: true,
            pda_seeds: vec![],
            identity: AccountIdentity::Unverified,
            expected_address_mismatch: false,
            pda_mismatch: false,
            privilege_mismatch: false,
        }
    }

    fn report(owner: &str, before: &[u8], after: &[u8]) -> StateDiffReport {
        let diff = StateDiff {
            deltas: vec![AccountDelta {
                pubkey: MINT.to_string(),
                before: Some(AccountSnapshot::from_raw(MINT, 5_000_000, owner, before)),
                after: Some(AccountSnapshot::from_raw(MINT, 5_000_000, owner, after)),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
            artifact_balance_writes: None,
            artifact_account_universe: None,
            artifact_accounts_undescribed: None,
            transfer_fee_mints: Default::default(),
            token2022_executed: None,
            fee_epoch: None,
            token2022_mints: Default::default(),
            transaction_accounts: None,
            transaction_privileges: None,
        };
        let declared: Vec<String> = DECLARED.iter().map(|s| s.to_string()).collect();
        check_state_diff(&StateDiffCheck {
            diff: &diff,
            resolved_accounts: &[writable(MINT)],
            privileges_grounded: true,
            expected_state_changes: &declared,
            fee_payer: None,
        })
    }

    fn codes(r: &StateDiffReport) -> Vec<&str> {
        r.findings.iter().map(|f| f.code.as_str()).collect()
    }

    /// A Token-2022 mint: the 82-byte base (initialized, no authorities),
    /// padding to 165, the Mint account type, then the TLV entries given.
    fn t22_mint(extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut d = vec![0u8; TOKEN_ACCOUNT_LEN];
        d[44] = 6;
        d[45] = 1;
        d.push(1); // AccountType::Mint
        for (ty, value) in extensions {
            d.extend_from_slice(&ty.to_le_bytes());
            d.extend_from_slice(&(value.len() as u16).to_le_bytes());
            d.extend_from_slice(value);
        }
        d
    }

    fn key_then(key: u8, rest: &[u8]) -> Vec<u8> {
        let mut v = vec![key; 32];
        v.extend_from_slice(rest);
        v
    }

    #[test]
    fn a_transfer_hook_authority_changing_hands_is_critical() {
        let program = [9u8; 32];
        let before = t22_mint(&[(14, key_then(2, &program))]);
        let after = t22_mint(&[(14, key_then(66, &program))]);
        let r = report(SPL_TOKEN_2022_PROGRAM, &before, &after);
        assert!(r.blocked, "{:?}", r.findings);
        assert!(
            codes(&r).contains(&"UndeclaredToken2022AuthorityChange"),
            "{:?}",
            r.findings
        );
    }

    #[test]
    fn a_metadata_update_authority_and_a_pause_are_critical() {
        let before = t22_mint(&[(19, key_then(2, &[7u8; 40])), (26, key_then(3, &[0]))]);
        let after = t22_mint(&[(19, key_then(66, &[7u8; 40])), (26, key_then(3, &[1]))]);
        let r = report(SPL_TOKEN_2022_PROGRAM, &before, &after);
        let c = codes(&r);
        assert!(c.contains(&"UndeclaredToken2022AuthorityChange"), "{c:?}");
        assert!(c.contains(&"UndeclaredToken2022Pause"), "{c:?}");
    }

    #[test]
    fn unchanged_extension_authorities_are_not_an_authority_change() {
        let mint = t22_mint(&[(18, key_then(2, &[8u8; 32])), (26, key_then(3, &[0]))]);
        let r = report(SPL_TOKEN_2022_PROGRAM, &mint, &mint);
        let c = codes(&r);
        assert!(!c.contains(&"UndeclaredToken2022AuthorityChange"), "{c:?}");
        assert!(!c.contains(&"UndeclaredToken2022Pause"), "{c:?}");
    }

    fn nonce(authority: u8) -> Vec<u8> {
        let mut d = vec![0u8; 80];
        d[0..4].copy_from_slice(&1u32.to_le_bytes());
        d[4..8].copy_from_slice(&1u32.to_le_bytes());
        d[8..40].copy_from_slice(&[authority; 32]);
        d[40..72].copy_from_slice(&[5u8; 32]);
        d
    }

    #[test]
    fn a_nonce_authority_changing_hands_is_critical() {
        let r = report(SYSTEM_PROGRAM, &nonce(2), &nonce(66));
        assert!(
            codes(&r).contains(&"UndeclaredNativeAuthorityChange"),
            "{:?}",
            r.findings
        );
        // Advancing the nonce (a new stored blockhash) is not an authority change.
        let mut advanced = nonce(2);
        advanced[40..72].copy_from_slice(&[6u8; 32]);
        let r = report(SYSTEM_PROGRAM, &nonce(2), &advanced);
        assert!(
            !codes(&r).contains(&"UndeclaredNativeAuthorityChange"),
            "{:?}",
            r.findings
        );
    }

    #[test]
    fn a_program_rewritten_under_the_same_authority_is_critical() {
        let program_data = |code: u8| {
            let mut d = vec![0u8; 45];
            d[0..4].copy_from_slice(&3u32.to_le_bytes());
            d[12] = 1;
            d[13..45].copy_from_slice(&[2u8; 32]);
            d.extend_from_slice(&[code; 64]);
            d
        };
        let r = report(
            "BPFLoaderUpgradeab1e11111111111111111111111",
            &program_data(1),
            &program_data(2),
        );
        assert!(
            codes(&r).contains(&"UndeclaredNativeAuthorityChange"),
            "{:?}",
            r.findings
        );
    }

    #[test]
    fn lookup_table_and_vote_withdrawer_authorities_are_watched() {
        let alt = |auth: u8| {
            let mut d = vec![0u8; 56];
            d[0..4].copy_from_slice(&1u32.to_le_bytes());
            d[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
            d[21] = 1;
            d[22..54].copy_from_slice(&[auth; 32]);
            d
        };
        let r = report(
            "AddressLookupTab1e1111111111111111111111111",
            &alt(2),
            &alt(66),
        );
        assert!(
            codes(&r).contains(&"UndeclaredNativeAuthorityChange"),
            "{:?}",
            r.findings
        );
        let vote = |withdrawer: u8| {
            let mut d = vec![0u8; 3762];
            d[0..4].copy_from_slice(&2u32.to_le_bytes());
            d[4..36].copy_from_slice(&[4u8; 32]);
            d[36..68].copy_from_slice(&[withdrawer; 32]);
            d
        };
        let r = report(
            "Vote111111111111111111111111111111111111111",
            &vote(2),
            &vote(66),
        );
        assert!(
            codes(&r).contains(&"UndeclaredNativeAuthorityChange"),
            "{:?}",
            r.findings
        );
    }
}

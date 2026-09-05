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
        Self {
            pubkey: pubkey.to_string(),
            lamports,
            owner: owner.to_string(),
            data_len: data.len(),
            token,
            mint,
        }
    }
}

fn pubkey_at(data: &[u8], offset: usize) -> Option<String> {
    let bytes = data.get(offset..offset + 32)?;
    Some(bs58::encode(bytes).into_string())
}

/// An on-chain COption<Pubkey>: a 4-byte little-endian tag followed by the key.
/// Tag 0 is None; anything else is Some. A Some whose key is all zeroes is
/// still treated as None, because that is what it means in practice.
fn coption_pubkey(data: &[u8], tag_offset: usize) -> Option<String> {
    let tag = u32::from_le_bytes(data.get(tag_offset..tag_offset + 4)?.try_into().ok()?);
    if tag == 0 {
        return None;
    }
    let key = pubkey_at(data, tag_offset + 4)?;
    if key == NULL_PUBKEY {
        None
    } else {
        Some(key)
    }
}

fn u64_at(data: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        data.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

/// Decode the 165-byte SPL token account layout, shared by Token and
/// Token-2022. Returns `None` when the data is not a token account.
pub fn decode_token_account(data: &[u8]) -> Option<TokenAccountView> {
    if data.len() < TOKEN_ACCOUNT_LEN {
        return None;
    }
    // A Token-2022 account longer than the base layout carries an explicit
    // type byte; anything longer that does NOT say "account" is a mint or an
    // unknown extension, and must not be decoded as an account.
    if data.len() > TOKEN_ACCOUNT_LEN {
        match data.get(T22_TYPE_OFFSET) {
            Some(&T22_TYPE_ACCOUNT) => {}
            _ => return None,
        }
    }
    let view = TokenAccountView {
        mint: pubkey_at(data, 0)?,
        owner: pubkey_at(data, 32)?,
        amount: u64_at(data, 64)?,
        delegate: coption_pubkey(data, 72),
        state: *data.get(108)?,
        delegated_amount: u64_at(data, 121)?,
        close_authority: coption_pubkey(data, 129),
    };
    // An uninitialized account is not a token account in any meaningful sense;
    // treating it as one would report a spurious 0-amount balance.
    if view.state == 0 {
        return None;
    }
    Some(view)
}

/// Decode the 82-byte SPL mint layout. Returns `None` when the data is not a
/// mint.
pub fn decode_mint(data: &[u8]) -> Option<MintView> {
    if data.len() < MINT_LEN {
        return None;
    }
    // Exactly-82 is a classic mint. Longer data must carry the Token-2022 type
    // byte saying "mint" — otherwise a 165-byte token account would decode as
    // a mint too, and its owner field would be misread as a supply.
    if data.len() != MINT_LEN {
        match data.get(T22_TYPE_OFFSET) {
            Some(&T22_TYPE_MINT) => {}
            _ => return None,
        }
    }
    let is_initialized = *data.get(45)? != 0;
    if !is_initialized {
        return None;
    }
    Some(MintView {
        mint_authority: coption_pubkey(data, 0),
        supply: u64_at(data, 36)?,
        decimals: *data.get(44)?,
        freeze_authority: coption_pubkey(data, 46),
    })
}

/// What changed for one account between pre-state and post-state.
///
/// `None` on either side means the account did not exist at that point:
/// `before: None` is a creation, `after: None` is a full close.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
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
    /// Signed mint supply movement, when both sides decode as mints.
    pub fn supply_delta(&self) -> Option<i128> {
        let b = self.before.as_ref()?.mint.as_ref()?;
        let a = self.after.as_ref()?.mint.as_ref()?;
        Some(i128::from(a.supply) - i128::from(b.supply))
    }
    /// A delegate that exists after the transaction and did not before.
    pub fn delegate_granted(&self) -> Option<String> {
        let after = self.after.as_ref()?.token.as_ref()?.delegate.clone()?;
        let before = self
            .before
            .as_ref()
            .and_then(|s| s.token.as_ref())
            .and_then(|t| t.delegate.clone());
        if before.as_deref() == Some(after.as_str()) {
            None
        } else {
            Some(after)
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
    /// True when nothing this module can observe actually changed.
    pub fn is_noop(&self) -> bool {
        self.before == self.after
    }
}

/// A complete pre/post picture of a transaction's effect on account state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StateDiff {
    pub deltas: Vec<AccountDelta>,
    #[serde(default)]
    pub provenance: DiffProvenance,
    /// Transaction fee in lamports, needed to check lamport conservation.
    #[serde(default)]
    pub fee_lamports: u64,
    /// True when every account the transaction could write was snapshotted.
    /// Only then is the lamport-conservation identity meaningful.
    #[serde(default)]
    pub covers_all_writable: bool,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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

    pub fn parse(expected_state_changes: &[String]) -> Self {
        let mut e = Self {
            absent: expected_state_changes.is_empty(),
            ..Self::default()
        };
        for raw in expected_state_changes {
            let c = raw.to_lowercase();
            // Value leaving an account.
            if c.contains("debit")
                || c.contains("transfer")
                || c.contains("swap")
                || c.contains("withdraw")
                || c.contains("deposit")
                || c.contains("repay")
                || c.contains("borrow")
                || c.contains("stake")
                || c.contains("unstake")
                || c.contains("send")
                || c.contains("pay")
                || c.contains("fee")
            {
                e.debit = true;
                e.credit = true;
            }
            if c.contains("credit") || c.contains("receive") || c.contains("reward") {
                e.credit = true;
            }
            if c.contains("close") || c.contains("closure") {
                e.close = true;
            }
            if c.contains("create")
                || c.contains("initialize")
                || c.contains("init ")
                || c.contains("open")
                || c.contains("allocate")
                || c.contains("new account")
            {
                e.create = true;
            }
            if c.contains("delegate") || c.contains("approve") {
                e.delegate = true;
            }
            if c.contains("authority") || c.contains("assign") || c.contains("owner") {
                e.authority = true;
            }
            if c.contains("mint") {
                e.mint = true;
            }
            if c.contains("burn") {
                e.burn = true;
            }
            if c.contains("freeze") || c.contains("thaw") {
                e.freeze = true;
            }
        }
        e.unrecognised = !e.absent
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

/// Compare an observed state diff against a manifest's declared effects.
///
/// This never returns a layer status — the caller maps findings and provenance
/// onto `LayerStatus`, because the provenance rule is a pipeline policy, not a
/// property of the diff (P7: a verdict is computed at the layer that owns it).
pub fn check_state_diff(input: &StateDiffCheck<'_>) -> StateDiffReport {
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

    let changed: Vec<&AccountDelta> = input.diff.changed().collect();

    // ── Diff integrity ──────────────────────────────────────────────────────
    //
    // Checked before anything is inferred FROM the diff, because a diff that
    // fails these is not evidence of anything.

    if input.diff.covers_all_writable {
        let sum: i128 = input.diff.deltas.iter().map(|d| d.lamport_delta()).sum();
        let expected = -i128::from(input.diff.fee_lamports);
        if sum != expected {
            findings.push(StateDiffFinding::critical(
                "LamportsNotConserved",
                None,
                format!(
                    "state diff claims to cover every writable account but lamport changes sum to {sum}, not {expected} (fee {}). Solana conserves lamports — the diff is incomplete or fabricated",
                    input.diff.fee_lamports
                ),
            ));
        }
    }

    for d in &changed {
        if !known_accounts.contains(d.pubkey.as_str()) {
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

    let mut net_lamport_out: i128 = 0;
    let mut token_debit = false;

    for d in &changed {
        let acct = Some(d.pubkey.as_str());
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
            && !declared.create
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
            let allocation =
                from == SYSTEM_PROGRAM && d.before.as_ref().is_some_and(|s| s.data_len == 0);
            if !(allocation && declared.create) && !declared.authority {
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
        if d.was_closed() && !declared.close {
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
            if !declared.delegate && !declared.authority {
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
            if !declared.close && !declared.authority {
                findings.push(StateDiffFinding::critical(
                    "UndeclaredCloseAuthorityGrant",
                    acct,
                    format!(
                        "token close authority set to {close_authority}; the manifest declares no authority change"
                    ),
                ));
            }
        }
        if d.was_frozen() && !declared.freeze {
            findings.push(StateDiffFinding::critical(
                "UndeclaredAccountFreeze",
                acct,
                "token account frozen; the manifest declares no freeze",
            ));
        }

        // Mint supply.
        match d.supply_delta() {
            Some(delta) if delta > 0 && !declared.mint => {
                findings.push(StateDiffFinding::critical(
                    "UndeclaredMint",
                    acct,
                    format!("mint supply increased by {delta}; the manifest declares no mint"),
                ));
            }
            Some(delta) if delta < 0 && !declared.burn => {
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

        // Value movement, accumulated and judged once below. The fee payer's
        // fee-sized outflow is expected on every transaction and is excluded.
        let lam = d.lamport_delta();
        if lam < 0 {
            let magnitude = -lam;
            let fee = i128::from(input.diff.fee_lamports);
            if !(is_fee_payer && magnitude <= fee) {
                net_lamport_out += magnitude - if is_fee_payer { fee } else { 0 };
            }
        }
        if d.token_delta().is_some_and(|t| t < 0) {
            token_debit = true;
        }
    }

    // A manifest that promises nothing cannot be contradicted, so value
    // movement is only judged when there is prose to judge it against. Prose
    // Graphite could not interpret warns instead of blocking — the manifest is
    // describing something, and punishing it for wording Graphite does not
    // know would block legitimate protocols (P12).
    if !declared.is_silent() && !declared.debit {
        if token_debit {
            let detail = "token balances decreased but the manifest declares no debit";
            findings.push(if declared.is_interpretable() {
                StateDiffFinding::critical("UndeclaredTokenDebit", None, detail)
            } else {
                StateDiffFinding::warning(
                    "UninterpretableDeclarationWithTokenDebit",
                    None,
                    format!("{detail} — and none of its declared changes could be interpreted, so this is reported rather than blocked"),
                )
            });
        } else if net_lamport_out > 0 && !declared.create && !declared.close {
            // Account creation legitimately debits the payer for rent, and a
            // closure legitimately moves the whole balance out, so neither is
            // reported as an unexplained outflow.
            findings.push(StateDiffFinding::warning(
                "UnexplainedLamportOutflow",
                None,
                format!(
                    "{net_lamport_out} lamports left the transaction's accounts beyond the fee; the manifest declares no debit"
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
        };
        let accounts = [account(ALICE, true)];
        let report = check(
            &diff,
            &accounts,
            &["assign new authority to the account".to_string()],
        );
        assert!(!codes(&report).contains(&"UndeclaredOwnerReassignment"));
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
                }),
            }],
            provenance: DiffProvenance::RpcSimulated,
            fee_lamports: 0,
            covers_all_writable: false,
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

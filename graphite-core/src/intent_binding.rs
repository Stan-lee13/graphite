//! The request's stated parameters, bound to the transaction's bytes
//! (Round 36, F-003 / F-004).
//!
//! Until Round 36 the Core carried `ExtractedParameters` and compared none of
//! it: `amount`, `destination`, `input_token` and `output_token` travelled
//! with the request and were never read (the `extracted_output_token` the
//! FakeSwap check takes was an unused argument). A verdict could be
//! `executable_approved` for a System transfer of 100 SOL to the wrong
//! address under a request for 1 SOL to the right one: risk Clear said the
//! transaction was not a known attack, and nothing said it was the
//! transaction the user asked for. The agent guard bound what it built
//! itself; a direct `/verify` consumer had to, and nothing told it so.
//!
//! The contract now: an approval is executable only when every parameter the
//! intent states is tied to the bytes that carry it.
//!
//!   - [`Binding::Bound`]: every stated parameter matched.
//!   - [`Binding::Mismatch`]: a stated parameter disagrees with the bytes. The
//!     verdict is Blocked (`IntentMismatch`, or `SwapUnderbounded` /
//!     `WithdrawalUnderbounded` for a minimum output the chain would hold to
//!     less than was simulated).
//!   - [`Binding::Unbound`]: the intent states parameters the Core could not
//!     tie to the bytes: none were sent, an asset is named by a symbol, the
//!     instruction is one whose amount the Core does not decode, or there was
//!     no simulation to read an effect from. The verdict carries the
//!     non-inherent residual `intent_parameters` and is never executable.
//!   - [`Binding::NotApplicable`]: the intent states no amount, recipient or
//!     asset (close, revoke, create, configure, claim).
//!
//! What is bound, and from what:
//!
//!   transfer   System `Transfer`, `TransferWithSeed`, `CreateAccount`,
//!              `CreateAccountWithSeed`, `WithdrawNonceAccount`; SPL Token and
//!              Token-2022 `Transfer` (its mint from the simulated pre-state),
//!              `TransferChecked`, Token-2022 `TransferCheckedWithFee`. Every
//!              such top-level instruction must move the requested asset from
//!              one signing authority to the requested destination (or its
//!              associated token account under the instruction's own token
//!              program), and together they must move exactly the requested
//!              amount.
//!   approve    `Approve` / `ApproveChecked`: the delegate is the requested
//!              destination, the allowance exactly the requested amount, of
//!              the requested mint.
//!   burn       `Burn` / `BurnChecked`: exactly the requested amount of the
//!              requested mint.
//!   swap       exactly one exact-in instruction the Core decodes (the agent
//!              guard's set: Jupiter v6 `route` / `shared_accounts_route`,
//!              Orca Whirlpools `swap` / `swapV2`, Raydium CLMM `swap` /
//!              `swap_v2`, Raydium CPMM `swap_base_input`, Raydium AMM v4
//!              `SwapBaseIn`, Meteora DLMM `swap` / `swap2`), whose amount in
//!              is at most the requested amount; and, from the simulated
//!              state diff, the fee payer spends no more than that (plus
//!              [`SWAP_SOL_OVERHEAD_LAMPORTS`] of SOL), spends no other token,
//!              receives the requested output, and the route's minimum output
//!              is within the slippage (the request's `slippage_bps`, at most
//!              [`SLIPPAGE_CEILING_BPS`], else [`DEFAULT_SLIPPAGE_BPS`]) of what
//!              the simulation delivered.
//!   withdraw   (a grant's `minimum_outputs`) each minimum the chain enforces
//!              is within the same slippage of what the simulation delivered
//!              to the account it bounds. A withdrawal whose instruction
//!              carries no minimum is unbound.
//!   stake      not bound: the Core decodes no stake amount.
//!
//! What is NOT judged here: a price. Whether a swap's simulated output is a
//! fair price is a question for a floor someone agreed to (the guard's
//! `GRAPHITE_SWAP_MIN_RATES`, or the request's own "for at least …"); the
//! Core holds the minimum to the simulation, which bounds what a front-runner
//! can take between simulation and landing, and does not say the pool's price
//! was a good one.
//!
//! Amounts are decimal strings in the asset's display units ("1.5"), read
//! exactly: no sign, exponent, separator or whitespace, no more fractional
//! digits than the asset has. "SOL" (any case) is native SOL; anything else
//! must be a mint address. A symbol is unbound, not guessed at.

use crate::solana_types::{find_program_address, Pubkey};
use crate::state_diff::{StateDiff, SPL_TOKEN_2022_PROGRAM, SPL_TOKEN_PROGRAM};
use crate::verification::ExtractedParameters;
use std::collections::BTreeMap;

pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
pub const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
pub const NATIVE_MINT: &str = "So11111111111111111111111111111111111111112";

pub const JUPITER_V6: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
pub const ORCA_WHIRLPOOLS: &str = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc";
pub const RAYDIUM_CPMM: &str = "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C";
pub const RAYDIUM_CLMM: &str = "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK";
pub const RAYDIUM_AMM_V4: &str = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";
pub const METEORA_DLMM: &str = "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo";

/// The programs whose swap instruction [`decode_swap`] reads.
pub const DECODED_SWAP_PROGRAMS: [&str; 6] = [
    JUPITER_V6,
    ORCA_WHIRLPOOLS,
    RAYDIUM_CPMM,
    RAYDIUM_CLMM,
    RAYDIUM_AMM_V4,
    METEORA_DLMM,
];

/// The slippage a minimum output may sit below the simulated output when the
/// request states none: 1%, the agent guard's `DEFAULT_SWAP_MAX_SLIPPAGE_BPS`.
pub const DEFAULT_SLIPPAGE_BPS: u64 = 100;
/// The most a request may state: 5%, the guard's `SWAP_SLIPPAGE_CEILING_BPS`.
pub const SLIPPAGE_CEILING_BPS: u64 = 500;
/// What a swap may spend in SOL beyond the amount requested (fee, priority
/// fee, rent for accounts a route creates): 0.01 SOL, the guard's
/// `SWAP_SOL_OVERHEAD_LAMPORTS`.
pub const SWAP_SOL_OVERHEAD_LAMPORTS: u128 = 10_000_000;
/// An amount string longer than this is not an amount.
const MAX_AMOUNT_TEXT: usize = 40;

/// The wire name of the risk finding a disagreement produces.
pub const INTENT_MISMATCH: &str = "IntentMismatch";
pub const SWAP_UNDERBOUNDED: &str = "SwapUnderbounded";
pub const WITHDRAWAL_UNDERBOUNDED: &str = "WithdrawalUnderbounded";

/// The outcome for one verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binding {
    NotApplicable,
    Bound(String),
    Unbound(String),
    Mismatch {
        pattern: &'static str,
        reason: String,
    },
}

impl Binding {
    fn mismatch(reason: impl Into<String>) -> Self {
        Binding::Mismatch {
            pattern: INTENT_MISMATCH,
            reason: reason.into(),
        }
    }
    fn unbound(reason: impl Into<String>) -> Self {
        Binding::Unbound(reason.into())
    }
}

/// One top-level instruction with every account resolved to an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ix {
    pub program_id: String,
    pub accounts: Vec<String>,
    pub data: Vec<u8>,
}

/// What the binding reads.
pub struct BindingInput<'a> {
    /// `risk_engine::canonical_intent` of the request's intent.
    pub canonical_intent: &'a str,
    pub params: Option<&'a ExtractedParameters>,
    /// The transaction's top-level instructions, every account resolved.
    /// `Err` says why they are not available (no artifact, unresolved lookup
    /// tables, an account index out of range).
    pub instructions: Result<&'a [Ix], &'a str>,
    /// The message's signers, fee payer first.
    pub signers: &'a [String],
    /// The diff Graphite built from a simulation; never a caller's.
    pub diff: Option<&'a StateDiff>,
    /// Decimals of mints Graphite read (fetched, or in the diff).
    pub mint_decimals: &'a BTreeMap<String, u8>,
}

/// The asset a request names.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Asset {
    Native,
    Mint(String),
}

impl Asset {
    fn describe(&self) -> String {
        match self {
            Asset::Native => "SOL".to_string(),
            Asset::Mint(m) => m.clone(),
        }
    }
}

/// Read an asset: "SOL" is native; a 32-byte base58 key is a mint.
fn read_asset(text: &str, field: &str) -> Result<Asset, String> {
    if text.eq_ignore_ascii_case("sol") {
        return Ok(Asset::Native);
    }
    match Pubkey::from_base58(text) {
        Ok(_) => Ok(Asset::Mint(text.to_string())),
        Err(_) => Err(format!(
            "the request names its {field} as {:?}, which is not a mint address: the Core binds an asset by its mint, and does not guess which token a symbol means",
            truncate(text)
        )),
    }
}

fn truncate(text: &str) -> String {
    text.chars().take(48).collect()
}

/// An exact decimal amount in base units, or why not.
pub fn parse_amount(text: &str, decimals: u8) -> Result<u64, String> {
    if text.is_empty() || text.len() > MAX_AMOUNT_TEXT {
        return Err(format!("the amount {:?} is not an amount", truncate(text)));
    }
    let (whole, fraction) = match text.split_once('.') {
        Some((w, f)) => (w, f),
        None => (text, ""),
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(whole) || (text.contains('.') && !digits(fraction)) {
        return Err(format!(
            "the amount {:?} is not a plain decimal (digits, at most one '.', nothing else)",
            truncate(text)
        ));
    }
    if fraction.len() > usize::from(decimals) {
        return Err(format!(
            "the amount {text} has more decimal places than the asset's {decimals}"
        ));
    }
    let scale = 10u128.pow(u32::from(decimals));
    let whole: u128 = whole
        .parse()
        .map_err(|_| format!("the amount {text} does not fit in a u64"))?;
    let mut frac = fraction.to_string();
    while frac.len() < usize::from(decimals) {
        frac.push('0');
    }
    let frac: u128 = if frac.is_empty() {
        0
    } else {
        frac.parse()
            .map_err(|_| format!("the amount {text} is not a plain decimal"))?
    };
    let units = whole
        .checked_mul(scale)
        .and_then(|w| w.checked_add(frac))
        .filter(|u| *u <= u128::from(u64::MAX))
        .ok_or_else(|| format!("the amount {text} does not fit in a u64"))?;
    if units == 0 {
        return Err(format!("the amount {text} is zero"));
    }
    Ok(units as u64)
}

fn le_u64(data: &[u8], at: usize) -> Option<u64> {
    data.get(at..at + 8)
        .map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes")))
}

fn le_u32(data: &[u8], at: usize) -> Option<u32> {
    data.get(at..at + 4)
        .map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")))
}

/// Whether `account` is `owner`'s associated token account for `mint` under
/// `token_program` — the program executing the instruction, not either.
pub fn is_ata_under(account: &str, owner: &str, mint: &str, token_program: &str) -> bool {
    let (Ok(account), Ok(owner), Ok(mint), Ok(tp), Ok(ata)) = (
        Pubkey::from_base58(account),
        Pubkey::from_base58(owner),
        Pubkey::from_base58(mint),
        Pubkey::from_base58(token_program),
        Pubkey::from_base58(ATA_PROGRAM),
    ) else {
        return false;
    };
    find_program_address(&[owner.as_bytes(), tp.as_bytes(), mint.as_bytes()], &ata)
        .is_ok_and(|(derived, _)| derived == account)
}

// ── Value movements ─────────────────────────────────────────────────────────

/// A top-level instruction that moves value, read the way its program reads
/// its data: a prefix, trailing bytes ignored (the System program's
/// `limited_deserialize` and the token programs' `unpack` both ignore them).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Movement {
    what: &'static str,
    /// The signing authority the value leaves under.
    authority: String,
    /// Where it goes: a system account, a token account, or a delegate.
    to: String,
    amount: u64,
    kind: MovementKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MovementKind {
    Lamports,
    /// A token movement. `mint`/`decimals` are `None` where the instruction
    /// does not carry them.
    Token {
        program: String,
        source: String,
        mint: Option<String>,
        decimals: Option<u8>,
        op: TokenOp,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenOp {
    Transfer,
    Approve,
    Burn,
}

fn account(ix: &Ix, i: usize) -> Option<String> {
    ix.accounts.get(i).cloned()
}

/// The System program's value movements.
fn system_movement(ix: &Ix) -> Option<Result<Movement, String>> {
    let tag = le_u32(&ix.data, 0)?;
    let short = |what: &str| Err(format!("a System {what} whose data or accounts are short"));
    let m =
        |what: &'static str, authority: Option<String>, to: Option<String>, amount: Option<u64>| {
            match (authority, to, amount) {
                (Some(authority), Some(to), Some(amount)) => Ok(Movement {
                    what,
                    authority,
                    to,
                    amount,
                    kind: MovementKind::Lamports,
                }),
                _ => short(what),
            }
        };
    Some(match tag {
        // CreateAccount { lamports, space, owner }: [funder, new].
        0 => m(
            "CreateAccount",
            account(ix, 0),
            account(ix, 1),
            le_u64(&ix.data, 4),
        ),
        // Transfer { lamports }: [from, to].
        2 => m(
            "Transfer",
            account(ix, 0),
            account(ix, 1),
            le_u64(&ix.data, 4),
        ),
        // CreateAccountWithSeed { base, seed: String, lamports, space, owner }:
        // [funder, created, (base)].
        3 => {
            let lamports = le_u64(&ix.data, 36).and_then(|len| {
                let at = 44usize.checked_add(usize::try_from(len).ok()?)?;
                le_u64(&ix.data, at)
            });
            m(
                "CreateAccountWithSeed",
                account(ix, 0),
                account(ix, 1),
                lamports,
            )
        }
        // WithdrawNonceAccount { lamports }: [nonce, to, recent_blockhashes, rent, authority].
        5 => m(
            "WithdrawNonceAccount",
            account(ix, 4),
            account(ix, 1),
            le_u64(&ix.data, 4),
        ),
        // TransferWithSeed { lamports, from_seed: String, from_owner }:
        // [from (derived), base (signer), to]. The base signs for it.
        11 => m(
            "TransferWithSeed",
            account(ix, 1),
            account(ix, 2),
            le_u64(&ix.data, 4),
        ),
        _ => return None,
    })
}

/// A token program's value movements (both programs share these tags).
fn token_movement(ix: &Ix) -> Option<Result<Movement, String>> {
    let tag = *ix.data.first()?;
    let program = ix.program_id.clone();
    let token = |what: &'static str,
                 op: TokenOp,
                 source: Option<String>,
                 mint: Option<Option<String>>,
                 to: Option<String>,
                 authority: Option<String>,
                 amount: Option<u64>,
                 decimals: Option<Option<u8>>| {
        match (source, mint, to, authority, amount, decimals) {
            (Some(source), Some(mint), Some(to), Some(authority), Some(amount), Some(decimals)) => {
                Ok(Movement {
                    what,
                    authority,
                    to,
                    amount,
                    kind: MovementKind::Token {
                        program: program.clone(),
                        source,
                        mint,
                        decimals,
                        op,
                    },
                })
            }
            _ => Err(format!("a token {what} whose data or accounts are short")),
        }
    };
    let d = &ix.data;
    Some(match tag {
        // Transfer { amount }: [source, destination, authority].
        3 => token(
            "Transfer",
            TokenOp::Transfer,
            account(ix, 0),
            Some(None),
            account(ix, 1),
            account(ix, 2),
            le_u64(d, 1),
            Some(None),
        ),
        // Approve { amount }: [source, delegate, owner].
        4 => token(
            "Approve",
            TokenOp::Approve,
            account(ix, 0),
            Some(None),
            account(ix, 1),
            account(ix, 2),
            le_u64(d, 1),
            Some(None),
        ),
        // Burn { amount }: [account, mint, owner]. Nothing receives it.
        8 => token(
            "Burn",
            TokenOp::Burn,
            account(ix, 0),
            account(ix, 1).map(Some),
            Some(String::new()),
            account(ix, 2),
            le_u64(d, 1),
            Some(None),
        ),
        // TransferChecked { amount, decimals }: [source, mint, destination, authority].
        12 => token(
            "TransferChecked",
            TokenOp::Transfer,
            account(ix, 0),
            account(ix, 1).map(Some),
            account(ix, 2),
            account(ix, 3),
            le_u64(d, 1),
            d.get(9).map(|x| Some(*x)),
        ),
        // ApproveChecked { amount, decimals }: [source, mint, delegate, owner].
        13 => token(
            "ApproveChecked",
            TokenOp::Approve,
            account(ix, 0),
            account(ix, 1).map(Some),
            account(ix, 2),
            account(ix, 3),
            le_u64(d, 1),
            d.get(9).map(|x| Some(*x)),
        ),
        // BurnChecked { amount, decimals }: [account, mint, owner].
        15 => token(
            "BurnChecked",
            TokenOp::Burn,
            account(ix, 0),
            account(ix, 1).map(Some),
            Some(String::new()),
            account(ix, 2),
            le_u64(d, 1),
            d.get(9).map(|x| Some(*x)),
        ),
        // Token-2022 TransferFeeExtension (26) / TransferCheckedWithFee (1)
        // { amount, decimals, fee }: [source, mint, destination, authority].
        26 if ix.program_id == SPL_TOKEN_2022_PROGRAM && d.get(1) == Some(&1) => token(
            "TransferCheckedWithFee",
            TokenOp::Transfer,
            account(ix, 0),
            account(ix, 1).map(Some),
            account(ix, 2),
            account(ix, 3),
            le_u64(d, 2),
            d.get(10).map(|x| Some(*x)),
        ),
        _ => return None,
    })
}

fn movements(ixs: &[Ix]) -> Result<Vec<Movement>, String> {
    let mut out = Vec::new();
    for ix in ixs {
        let m = if ix.program_id == SYSTEM_PROGRAM {
            system_movement(ix)
        } else if ix.program_id == SPL_TOKEN_PROGRAM || ix.program_id == SPL_TOKEN_2022_PROGRAM {
            token_movement(ix)
        } else {
            None
        };
        if let Some(m) = m {
            out.push(m?);
        }
    }
    Ok(out)
}

/// The mint of a token movement: the instruction's own, else the source
/// account's in the simulated pre-state.
fn movement_mint(source: &str, mint: &Option<String>, diff: Option<&StateDiff>) -> Option<String> {
    mint.clone().or_else(|| {
        diff?
            .deltas
            .iter()
            .find(|d| d.pubkey == source)?
            .before
            .as_ref()?
            .token
            .as_ref()
            .map(|t| t.mint.clone())
    })
}

fn decimals_of(mint: &str, input: &BindingInput<'_>) -> Option<u8> {
    if let Some(d) = input.mint_decimals.get(mint) {
        return Some(*d);
    }
    let diff = input.diff?;
    diff.deltas
        .iter()
        .find(|d| d.pubkey == mint)
        .and_then(|d| d.before.as_ref().or(d.after.as_ref()))
        .and_then(|s| s.mint.as_ref())
        .or_else(|| diff.token2022_mints.get(mint).and_then(|s| s.mint.as_ref()))
        .map(|m| m.decimals)
}

/// The mints whose decimals [`bind`] needs and the instructions may not
/// carry: the ones the request names by address, for an intent that binds
/// an amount. Graphite reads them from the RPC at pre-state.
pub fn mints_to_read(canonical_intent: &str, params: Option<&ExtractedParameters>) -> Vec<String> {
    if !matches!(canonical_intent, "transfer" | "approve" | "burn" | "swap") {
        return Vec::new();
    }
    let Some(p) = params else {
        return Vec::new();
    };
    let mut out: Vec<String> = [p.input_token.as_ref(), p.output_token.as_ref()]
        .into_iter()
        .flatten()
        .filter(|t| t.as_str() != NATIVE_MINT && Pubkey::from_base58(t).is_ok())
        .cloned()
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

// ── The entry point ─────────────────────────────────────────────────────────

/// Bind the request's parameters to the transaction (see the module comment).
pub fn bind(input: &BindingInput<'_>) -> Binding {
    match input.canonical_intent {
        "transfer" => bind_token_like(input, &[TokenOp::Transfer], true),
        "approve" => bind_token_like(input, &[TokenOp::Approve], false),
        "burn" => bind_token_like(input, &[TokenOp::Burn], false),
        "swap" => bind_swap(input),
        "stake" => Binding::unbound(
            "a stake states an amount, and the Core decodes no stake program's amount: the stake is not tied to what was asked",
        ),
        // A withdrawal's binding is its minimum outputs (`bind_withdrawal`),
        // judged where the grant is known.
        _ => Binding::NotApplicable,
    }
}

fn need<'p>(value: Option<&'p String>, name: &str, intent: &str) -> Result<&'p str, String> {
    match value.map(|s| s.as_str()) {
        Some(s) if !s.is_empty() => Ok(s),
        _ => Err(format!(
            "the request states no {name}: a {intent} binds its {name} to the bytes, and there is nothing to bind it to"
        )),
    }
}

/// Transfer, approve and burn: every movement of `ops` binds to the request.
fn bind_token_like(input: &BindingInput<'_>, ops: &[TokenOp], native_allowed: bool) -> Binding {
    let intent = input.canonical_intent;
    let Some(params) = input.params else {
        return Binding::unbound(format!(
            "the request carries no extracted_parameters: a {intent} states an amount and an asset{}, and none was sent to bind",
            if intent == "burn" { "" } else { " and a recipient" }
        ));
    };
    let amount_text = match need(params.amount.as_ref(), "amount", intent) {
        Ok(a) => a,
        Err(e) => return Binding::unbound(e),
    };
    let asset_text = match need(params.input_token.as_ref(), "asset (input_token)", intent) {
        Ok(a) => a,
        Err(e) => return Binding::unbound(e),
    };
    let asset = match read_asset(asset_text, "asset (input_token)") {
        Ok(a) => a,
        Err(e) => return Binding::unbound(e),
    };
    if asset == Asset::Native && !native_allowed {
        return Binding::mismatch(format!(
            "a {intent} acts on a token, and the request names SOL"
        ));
    }
    let destination = if intent == "burn" {
        None
    } else {
        let d = match need(params.destination.as_ref(), "destination", intent) {
            Ok(d) => d,
            Err(e) => return Binding::unbound(e),
        };
        if Pubkey::from_base58(d).is_err() {
            return Binding::unbound(format!(
                "the request's destination {:?} is not an address, so there is nothing to compare the transaction's with",
                truncate(d)
            ));
        }
        Some(d.to_string())
    };
    let ixs = match input.instructions {
        Ok(ixs) => ixs,
        Err(why) => {
            return Binding::unbound(format!(
                "the transaction's instructions are not readable ({why}), so its {intent} cannot be tied to the request"
            ))
        }
    };
    let moves = match movements(ixs) {
        Ok(m) => m,
        Err(e) => return Binding::mismatch(e),
    };
    // Every movement of the wrong family is a movement the request did not
    // ask for: a transfer request carrying an Approve, an approve carrying a
    // Transfer.
    let mut relevant = Vec::new();
    for m in &moves {
        let op = match &m.kind {
            MovementKind::Lamports => TokenOp::Transfer,
            MovementKind::Token { op, .. } => *op,
        };
        if ops.contains(&op) {
            relevant.push(m);
        } else {
            return Binding::mismatch(format!(
                "the request is a {intent}; the transaction also carries a {} of {} base units the request does not ask for",
                m.what, m.amount
            ));
        }
    }
    if relevant.is_empty() {
        return Binding::unbound(format!(
            "the transaction carries no top-level {intent} instruction the Core reads (System, SPL Token or Token-2022), so what it moves is not tied to the request"
        ));
    }
    let authority = relevant[0].authority.clone();
    let mut total: u128 = 0;
    let mut decimals_seen: Option<u8> = None;
    for m in &relevant {
        if m.authority != authority {
            return Binding::mismatch(format!(
                "the transaction moves value under two authorities ({} and {}); a {intent} request names one",
                authority, m.authority
            ));
        }
        // No signer set (a described request without its signer flags): the
        // authority cannot be checked, and the binding is not claimed below.
        if !input.signers.is_empty() && !input.signers.iter().any(|s| s == &m.authority) {
            return Binding::mismatch(format!(
                "the {} moves value under {}, which does not sign this transaction",
                m.what, m.authority
            ));
        }
        match (&m.kind, &asset) {
            (MovementKind::Lamports, Asset::Native) => {
                if let Some(dest) = &destination {
                    if &m.to != dest {
                        return Binding::mismatch(format!(
                            "the {} sends {} lamports to {}; the request's destination is {dest}",
                            m.what, m.amount, m.to
                        ));
                    }
                }
                decimals_seen = Some(9);
            }
            (MovementKind::Lamports, Asset::Mint(mint)) => {
                return Binding::mismatch(format!(
                    "the {} moves native SOL; the request names the token {mint}",
                    m.what
                ))
            }
            (MovementKind::Token { .. }, Asset::Native) => {
                return Binding::mismatch(format!(
                    "the {} moves a token; the request names native SOL",
                    m.what
                ))
            }
            (
                MovementKind::Token {
                    program,
                    source,
                    mint: ix_mint,
                    decimals,
                    ..
                },
                Asset::Mint(mint),
            ) => {
                let Some(actual) = movement_mint(source, ix_mint, input.diff) else {
                    return Binding::unbound(format!(
                        "the {} names no mint and its source account's mint was not read from a simulation, so the token it moves is not known",
                        m.what
                    ));
                };
                if &actual != mint {
                    return Binding::mismatch(format!(
                        "the {} moves the token {actual}; the request names {mint}",
                        m.what
                    ));
                }
                if let Some(dest) = &destination {
                    if &m.to != dest && !is_ata_under(&m.to, dest, mint, program) {
                        return Binding::mismatch(format!(
                            "the {} {} {}, which is neither the request's destination {dest} nor its associated token account for {mint}",
                            m.what,
                            if intent == "approve" { "delegates to" } else { "pays" },
                            m.to
                        ));
                    }
                }
                let d = match decimals.or_else(|| decimals_of(mint, input)) {
                    Some(d) => d,
                    None => {
                        return Binding::unbound(format!(
                            "the {} carries no decimals and the mint {mint} was not read, so the requested amount cannot be put in base units",
                            m.what
                        ))
                    }
                };
                if decimals_seen.is_some_and(|s| s != d) {
                    return Binding::mismatch(format!(
                        "the transaction's instructions state two different decimals ({} and {d}) for {mint}",
                        decimals_seen.unwrap_or_default()
                    ));
                }
                decimals_seen = Some(d);
            }
        }
        total += u128::from(m.amount);
    }
    let decimals = decimals_seen.unwrap_or(9);
    let requested = match parse_amount(amount_text, decimals) {
        Ok(r) => r,
        Err(e) => return Binding::unbound(e),
    };
    if total != u128::from(requested) {
        return Binding::mismatch(format!(
            "the transaction's {intent} amounts to {total} base units of {}; the request states {amount_text} ({requested} base units)",
            asset.describe()
        ));
    }
    if input.signers.is_empty() {
        return Binding::unbound(format!(
            "the {intent} matches the request's amount, asset and recipient, but the transaction's signers are not known, so the authority it moves value under is not tied to the request"
        ));
    }
    Binding::Bound(format!(
        "{intent} of {amount_text} {} ({requested} base units){} under {authority}, exactly as requested",
        asset.describe(),
        destination
            .map(|d| format!(" to {d}"))
            .unwrap_or_default()
    ))
}

// ── Swaps ───────────────────────────────────────────────────────────────────

/// What [`decode_swap`] read: the exact input spent and the least output
/// accepted, in base units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSwap {
    pub name: &'static str,
    pub amount_in: u64,
    pub min_out: u64,
}

/// A strict Borsh reader: every read bounds-checked, `end` requires the data
/// to be used up (Anchor ignores trailing bytes, so data that does not end
/// with its layout could be read two ways).
struct Reader<'a> {
    data: &'a [u8],
    at: usize,
    what: &'static str,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize, field: &str) -> Result<&'a [u8], String> {
        let end = self
            .at
            .checked_add(n)
            .filter(|e| *e <= self.data.len())
            .ok_or_else(|| format!("{}: the data ends inside {field}", self.what))?;
        let out = &self.data[self.at..end];
        self.at = end;
        Ok(out)
    }
    fn u8(&mut self, field: &str) -> Result<u8, String> {
        Ok(self.take(1, field)?[0])
    }
    fn u16(&mut self, field: &str) -> Result<u16, String> {
        let b = self.take(2, field)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self, field: &str) -> Result<u32, String> {
        let b = self.take(4, field)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self, field: &str) -> Result<u64, String> {
        let b = self.take(8, field)?;
        Ok(u64::from_le_bytes(b.try_into().expect("8 bytes")))
    }
    fn bool(&mut self, field: &str) -> Result<bool, String> {
        match self.u8(field)? {
            0 => Ok(false),
            1 => Ok(true),
            b => Err(format!("{}: {field} is {b}, not a Borsh bool", self.what)),
        }
    }
    fn option(&mut self, field: &str) -> Result<bool, String> {
        match self.u8(field)? {
            0 => Ok(false),
            1 => Ok(true),
            b => Err(format!("{}: {field} has Option tag {b}", self.what)),
        }
    }
    fn vec_len(&mut self, field: &str, max: u32) -> Result<u32, String> {
        let n = self.u32(field)?;
        if n > max {
            return Err(format!(
                "{}: {field} has {n} entries, more than {max}",
                self.what
            ));
        }
        Ok(n)
    }
    fn end(&self) -> Result<(), String> {
        if self.at != self.data.len() {
            return Err(format!(
                "{}: {} byte(s) follow the last argument, and the program ignores trailing bytes",
                self.what,
                self.data.len() - self.at
            ));
        }
        Ok(())
    }
}

/// The argument bytes each Jupiter v6 `Swap` variant carries
/// (graphite-core/scripts/idls/jupiter.json, variants 0..61). The same table
/// as `integrations/agent-guard/swap-instructions.ts`
/// (`JUPITER_SWAP_VARIANTS`); `tests/round36_intent_binding.rs` checks the
/// two agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JupiterPayload {
    Unit,
    Bool,
    Side,
    U64U64,
    U32,
    Clone,
    WhirlpoolV2,
}

use JupiterPayload as J;
pub const JUPITER_SWAP_VARIANTS: [JupiterPayload; 62] = [
    J::Unit,
    J::Unit,
    J::Unit,
    J::Unit,
    J::Unit,
    J::Unit,
    J::Unit,
    J::Unit, // 0-7
    J::Bool, // 8 Crema
    J::Unit,
    J::Unit,
    J::Unit, // 9-11
    J::Side, // 12 Serum
    J::Unit,
    J::Unit, // 13-14
    J::Side,
    J::Side, // 15-16 Aldrin, AldrinV2
    J::Bool,
    J::Bool, // 17-18 Whirlpool, Invariant
    J::Unit,
    J::Unit, // 19-20
    J::Bool, // 21 DeltaFi
    J::Unit, // 22
    J::Bool, // 23 MarcoPolo
    J::Side, // 24 Dradex
    J::Unit,
    J::Unit, // 25-26
    J::Side,
    J::Side,   // 27-28 Openbook, Phoenix
    J::U64U64, // 29 Symmetry
    J::Unit,
    J::Unit,
    J::Unit, // 30-32
    J::U32,  // 33 StakeDexSwapViaStake
    J::Unit,
    J::Unit,
    J::Unit,
    J::Unit,
    J::Unit,        // 34-38
    J::Side,        // 39 OpenBookV2
    J::Unit,        // 40
    J::Clone,       // 41 Clone
    J::WhirlpoolV2, // 42
    J::Unit,
    J::Unit,
    J::Unit,
    J::Unit,
    J::Unit,
    J::Unit,
    J::Unit,
    J::Unit,
    J::Unit,
    J::Unit, // 43-52
    J::Bool, // 53 Obric
    J::Unit, // 54
    J::Bool,
    J::Bool, // 55-56
    J::Unit,
    J::Unit, // 57-58
    J::Side, // 59 TokenMill
    J::Unit,
    J::Unit, // 60-61
];
const JUPITER_ACCOUNTS_TYPES: u8 = 2;
const WHIRLPOOL_ACCOUNTS_TYPES: u8 = 9;
const MAX_ROUTE_STEPS: u32 = 32;
const MAX_REMAINING_SLICES: u32 = 16;

fn remaining_accounts_info(
    r: &mut Reader<'_>,
    field: &str,
    unit_variants: u8,
    dlmm_multi_reward: bool,
) -> Result<(), String> {
    let n = r.vec_len(field, MAX_REMAINING_SLICES)?;
    for _ in 0..n {
        let t = r.u8(field)?;
        if dlmm_multi_reward && t == 3 {
            r.u8(field)?;
        } else if t >= unit_variants {
            return Err(format!(
                "{}: {field} has AccountsType {t}, which the committed IDL does not define",
                r.what
            ));
        }
        r.u8(field)?;
    }
    Ok(())
}

fn jupiter_route(data: &[u8], shared: bool, name: &'static str) -> Result<DecodedSwap, String> {
    let mut r = Reader {
        data,
        at: 8,
        what: name,
    };
    if shared {
        r.u8("id")?;
    }
    let steps = r.vec_len("route_plan", MAX_ROUTE_STEPS)?;
    if steps == 0 {
        return Err(format!("{name}: the route has no steps"));
    }
    for _ in 0..steps {
        let tag = r.u8("route_plan.swap")?;
        let kind = JUPITER_SWAP_VARIANTS.get(usize::from(tag)).ok_or_else(|| {
            format!("{name}: a step uses Swap variant {tag}, past the committed IDL's 62")
        })?;
        match kind {
            J::Unit => {}
            J::Bool => {
                r.bool("swap")?;
            }
            J::Side => {
                if r.u8("swap.side")? > 1 {
                    return Err(format!("{name}: a step's Side is not 0 or 1"));
                }
            }
            J::U64U64 => {
                r.u64("swap")?;
                r.u64("swap")?;
            }
            J::U32 => {
                r.u32("swap")?;
            }
            J::Clone => {
                r.u8("swap")?;
                r.bool("swap")?;
                r.bool("swap")?;
            }
            J::WhirlpoolV2 => {
                r.bool("swap")?;
                if r.option("swap.remaining_accounts_info")? {
                    remaining_accounts_info(
                        &mut r,
                        "swap.remaining_accounts_info",
                        JUPITER_ACCOUNTS_TYPES,
                        false,
                    )?;
                }
            }
        }
        r.u8("percent")?;
        r.u8("input_index")?;
        r.u8("output_index")?;
    }
    let amount_in = r.u64("in_amount")?;
    let quoted_out = r.u64("quoted_out_amount")?;
    let slippage_bps = r.u16("slippage_bps")?;
    let platform_fee_bps = r.u8("platform_fee_bps")?;
    r.end()?;
    if slippage_bps > 10_000 {
        return Err(format!("{name}: slippage_bps {slippage_bps} is over 100%"));
    }
    if platform_fee_bps != 0 {
        return Err(format!(
            "{name}: platform_fee_bps is {platform_fee_bps}, a fee taken from the output the route's minimum is computed on"
        ));
    }
    let min_out = (u128::from(quoted_out) * u128::from(10_000 - slippage_bps) / 10_000) as u64;
    Ok(DecodedSwap {
        name,
        amount_in,
        min_out,
    })
}

fn concentrated(
    data: &[u8],
    name: &'static str,
    a_to_b: bool,
    whirlpool_option: bool,
) -> Result<DecodedSwap, String> {
    let mut r = Reader {
        data,
        at: 8,
        what: name,
    };
    let amount = r.u64("amount")?;
    let threshold = r.u64("other_amount_threshold")?;
    r.take(16, "sqrt_price_limit")?;
    let exact_in = r.bool(if a_to_b {
        "amount_specified_is_input"
    } else {
        "is_base_input"
    })?;
    if a_to_b {
        r.bool("a_to_b")?;
    }
    if whirlpool_option && r.option("remaining_accounts_info")? {
        remaining_accounts_info(
            &mut r,
            "remaining_accounts_info",
            WHIRLPOOL_ACCOUNTS_TYPES,
            false,
        )?;
    }
    r.end()?;
    if !exact_in {
        return Err(format!(
            "{name} is exact-output: its input is bounded only by a maximum the route chose, so what it spends is not fixed by its bytes"
        ));
    }
    Ok(DecodedSwap {
        name,
        amount_in: amount,
        min_out: threshold,
    })
}

fn in_min(
    data: &[u8],
    at: usize,
    name: &'static str,
    dlmm_remaining: bool,
) -> Result<DecodedSwap, String> {
    let mut r = Reader {
        data,
        at,
        what: name,
    };
    let amount_in = r.u64("amount_in")?;
    let min_out = r.u64("minimum_amount_out")?;
    if dlmm_remaining {
        remaining_accounts_info(&mut r, "remaining_accounts_info", 3, true)?;
    }
    r.end()?;
    Ok(DecodedSwap {
        name,
        amount_in,
        min_out,
    })
}

/// Decode a swap instruction's data, or say why not. `None` when the program
/// is not one whose swaps the Core decodes.
pub fn decode_swap(program_id: &str, data: &[u8]) -> Option<Result<DecodedSwap, String>> {
    if !DECODED_SWAP_PROGRAMS.contains(&program_id) {
        return None;
    }
    let width = if program_id == RAYDIUM_AMM_V4 { 1 } else { 8 };
    let Some(selector) = data.get(..width) else {
        return Some(Err(format!(
            "{program_id}: the data is shorter than its selector"
        )));
    };
    let selector = hex::encode(selector);
    let decoded = match (program_id, selector.as_str()) {
        (JUPITER_V6, "e517cb977ae3ad2a") => jupiter_route(data, false, "Jupiter v6 route"),
        (JUPITER_V6, "c1209b3341d69c81") => jupiter_route(data, true, "Jupiter v6 shared_accounts_route"),
        (ORCA_WHIRLPOOLS, "f8c69e91e17587c8") => concentrated(data, "Orca Whirlpools swap", true, false),
        (ORCA_WHIRLPOOLS, "2b04ed0b1ac91e62") => concentrated(data, "Orca Whirlpools swapV2", true, true),
        (RAYDIUM_CLMM, "f8c69e91e17587c8") => concentrated(data, "Raydium CLMM swap", false, false),
        (RAYDIUM_CLMM, "2b04ed0b1ac91e62") => concentrated(data, "Raydium CLMM swap_v2", false, false),
        (RAYDIUM_CPMM, "8fbe5adac41e33de") => in_min(data, 8, "Raydium CPMM swap_base_input", false),
        (RAYDIUM_AMM_V4, "09") => in_min(data, 1, "Raydium AMM v4 SwapBaseIn", false),
        (METEORA_DLMM, "f8c69e91e17587c8") => in_min(data, 8, "Meteora DLMM swap", false),
        (METEORA_DLMM, "414b3f4ceb5b5b88") => in_min(data, 8, "Meteora DLMM swap2", true),
        _ => Err(format!(
            "instruction {selector} on {program_id} is not an exact-in swap whose data the Core decodes"
        )),
    };
    Some(decoded.and_then(|d| {
        if d.amount_in == 0 {
            Err(format!("{}: the input amount is 0", d.name))
        } else {
            Ok(d)
        }
    }))
}

/// The fee payer's net effect, from Graphite's own simulated diff.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WalletEffect {
    /// Native SOL leaving the wallet: its own lamports (fee and rent
    /// included) plus wrapped SOL in token accounts it owns. Negative when it
    /// gains.
    pub sol_out: i128,
    /// Wrapped SOL's net change in the wallet's token accounts (positive =
    /// received); already counted in `sol_out`.
    pub wrapped_sol_delta: i128,
    /// Every other mint's net change across the wallet's token accounts.
    pub token_delta: BTreeMap<String, i128>,
    /// Round 38 (R37-1): every lamport leaving the wallet and the token
    /// accounts it owns, rent and the fee included. Rent moved between the
    /// wallet and its own accounts (an associated token account created, a
    /// wSOL account closed to the wallet) nets out here, so for a swap that
    /// pays out SOL `-lamports_out` is what reached the signer, less the fee.
    pub lamports_out: i128,
}

/// The same reading as the guard's `walletEffectOf`: a token account the
/// wallet owned before counts as leaving, one it owns after as arriving.
pub fn wallet_effect(diff: &StateDiff, wallet: &str) -> WalletEffect {
    let mut e = WalletEffect::default();
    for d in &diff.deltas {
        if d.pubkey == wallet {
            e.sol_out += i128::from(d.lamports_before()) - i128::from(d.lamports_after());
            e.lamports_out += i128::from(d.lamports_before()) - i128::from(d.lamports_after());
        }
        for (snap, sign) in [(d.before.as_ref(), 1i128), (d.after.as_ref(), -1i128)] {
            let Some(s) = snap else {
                continue;
            };
            let Some(t) = s.token.as_ref() else {
                continue;
            };
            if t.owner != wallet {
                continue;
            }
            if d.pubkey != wallet {
                e.lamports_out += sign * i128::from(s.lamports);
            }
            let amount = i128::from(t.amount);
            if t.mint == NATIVE_MINT {
                e.sol_out += sign * amount;
                e.wrapped_sol_delta -= sign * amount;
            } else {
                *e.token_delta.entry(t.mint.clone()).or_default() -= sign * amount;
            }
        }
    }
    e
}

/// The slippage a minimum may sit below what was simulated.
fn slippage(params: Option<&ExtractedParameters>) -> Result<u64, Binding> {
    match params.and_then(|p| p.slippage_bps) {
        None => Ok(DEFAULT_SLIPPAGE_BPS),
        Some(s) if s < 0 => Err(Binding::unbound(format!(
            "the request's slippage_bps {s} is negative"
        ))),
        Some(s) if s as u64 > SLIPPAGE_CEILING_BPS => Err(Binding::Mismatch {
            pattern: SWAP_UNDERBOUNDED,
            reason: format!(
                "the request allows {s} bps of slippage; the Core allows at most {SLIPPAGE_CEILING_BPS}"
            ),
        }),
        Some(s) => Ok(s as u64),
    }
}

/// Whether `min_out` is within `bps` of `simulated`: min × 10⁴ ≥ simulated × (10⁴ − bps).
fn within_slippage(min_out: u64, simulated: i128, bps: u64) -> bool {
    i128::from(min_out) * 10_000 >= simulated * i128::from(10_000 - bps)
}

/// Whether `account` is a signer's own: a signer itself, or a token account a
/// signer owns before or after the simulation. An account the simulation did
/// not observe is nobody's the Core can vouch for.
fn signers_own(account: &str, signers: &[String], diff: &StateDiff) -> bool {
    if signers.iter().any(|s| s == account) {
        return true;
    }
    diff.deltas.iter().any(|d| {
        d.pubkey == account
            && [d.before.as_ref(), d.after.as_ref()]
                .into_iter()
                .flatten()
                .any(|s| s.token.as_ref().is_some_and(|t| signers.contains(&t.owner)))
    })
}

/// Round 38 (R37-1): nothing beside a swap or a withdrawal takes value from a
/// signer.
///
/// Round 36 tied a swap to its request by the route's decoded amounts and the
/// fee payer's NET change, and a withdrawal by its recipient's net credit. A
/// sibling could move value out of the same accounts and leave every net
/// inside its bound: the route paid 100 into the signer's account, a
/// `TransferChecked` beside it sent 49.6 of it on, and the 50.4 left still met
/// the minimum of 50 (`executable_approved`). Two rules, both from Graphite's
/// own reading:
///
/// - Every top-level System, SPL Token or Token-2022 instruction that moves
///   value under a signer's authority sends it to a signer's own account
///   (transfers, account creation, `CloseAccount`); one that hands a signer's
///   account to someone else (`Approve`, `SetAuthority`) or destroys value
///   (`Burn`) is a mismatch. These are read from the bytes.
/// - No account outside the signers' own and `route`'s gains lamports or a
///   token of `mints`. This is read from the diff, so a skim done by CPI from
///   any program is caught the same way.
fn keeps_value(
    what: &str,
    ixs: &[Ix],
    route: &[&Ix],
    signers: &[String],
    diff: &StateDiff,
    mints: &[String],
) -> Result<(), Binding> {
    let own = |a: &str| signers_own(a, signers, diff);
    let signer = |a: &str| signers.iter().any(|s| s == a);
    for (i, ix) in ixs.iter().enumerate() {
        if route.iter().any(|r| std::ptr::eq(*r, ix)) {
            continue;
        }
        let token_program =
            ix.program_id == SPL_TOKEN_PROGRAM || ix.program_id == SPL_TOKEN_2022_PROGRAM;
        let moved = if ix.program_id == SYSTEM_PROGRAM {
            system_movement(ix)
        } else if token_program {
            token_movement(ix)
        } else {
            None
        };
        match moved {
            Some(Err(e)) => {
                return Err(Binding::unbound(format!(
                    "{what}: instruction {i} beside it is unreadable ({e})"
                )))
            }
            Some(Ok(m)) if signer(&m.authority) => {
                let op = match &m.kind {
                    MovementKind::Token { op, .. } => Some(*op),
                    MovementKind::Lamports => None,
                };
                if op == Some(TokenOp::Burn) {
                    return Err(Binding::mismatch(format!(
                        "{what}: instruction {i} ({}) burns {} of a signer's tokens beside it",
                        m.what, m.amount
                    )));
                }
                if !own(&m.to) {
                    return Err(Binding::mismatch(format!(
                        "{what}: instruction {i} ({}) moves {} from a signer to {}, which is not a signer's own account",
                        m.what, m.amount, m.to
                    )));
                }
            }
            Some(Ok(_)) => {}
            None if token_program => {
                // CloseAccount { }: [account, destination, owner];
                // SetAuthority { .. }: [account, current authority].
                match ix.data.first() {
                    Some(9) => {
                        if let (Some(dest), Some(owner)) = (account(ix, 1), account(ix, 2)) {
                            if signer(&owner) && !own(&dest) {
                                return Err(Binding::mismatch(format!(
                                    "{what}: instruction {i} (CloseAccount) sends a signer's account's lamports to {dest}, which is not a signer's own account"
                                )));
                            }
                        }
                    }
                    Some(6) => {
                        if account(ix, 1).is_some_and(|a| signer(&a)) {
                            return Err(Binding::mismatch(format!(
                                "{what}: instruction {i} (SetAuthority) hands an authority a signer holds to someone else beside it"
                            )));
                        }
                    }
                    _ => {}
                }
            }
            None => {}
        }
    }
    let in_route = |a: &str| route.iter().any(|r| r.accounts.iter().any(|x| x == a));
    for d in &diff.deltas {
        if in_route(&d.pubkey) || own(&d.pubkey) {
            continue;
        }
        if d.lamport_delta() > 0 {
            return Err(Binding::mismatch(format!(
                "{what}: {} gained {} lamports, and it is neither a signer's account nor one of the route's",
                d.pubkey,
                d.lamport_delta()
            )));
        }
        let amount = |s: Option<&crate::state_diff::AccountSnapshot>, mint: &str| {
            s.and_then(|s| s.token.as_ref())
                .filter(|t| t.mint == mint)
                .map_or(0, |t| i128::from(t.amount))
        };
        for mint in mints {
            let gained = amount(d.after.as_ref(), mint) - amount(d.before.as_ref(), mint);
            if gained > 0 {
                return Err(Binding::mismatch(format!(
                    "{what}: {} gained {gained} base units of {mint}, and it is neither a signer's account nor one of the route's",
                    d.pubkey
                )));
            }
        }
    }
    Ok(())
}

fn bind_swap(input: &BindingInput<'_>) -> Binding {
    let Some(params) = input.params else {
        return Binding::unbound(
            "the request carries no extracted_parameters: a swap states an amount, an input and an output, and none was sent to bind",
        );
    };
    let (amount_text, in_text, out_text) = match (
        need(params.amount.as_ref(), "amount", "swap"),
        need(params.input_token.as_ref(), "input token", "swap"),
        need(params.output_token.as_ref(), "output token", "swap"),
    ) {
        (Ok(a), Ok(i), Ok(o)) => (a, i, o),
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => return Binding::unbound(e),
    };
    // A swap's SOL is wrapped SOL at the route.
    let mint_of = |a: Asset| match a {
        Asset::Native => NATIVE_MINT.to_string(),
        Asset::Mint(m) => m,
    };
    let (in_mint, out_mint) = match (
        read_asset(in_text, "input token"),
        read_asset(out_text, "output token"),
    ) {
        (Ok(i), Ok(o)) => (mint_of(i), mint_of(o)),
        (Err(e), _) | (_, Err(e)) => return Binding::unbound(e),
    };
    if in_mint == out_mint {
        return Binding::mismatch(format!("the request swaps {in_text} for itself"));
    }
    let bps = match slippage(Some(params)) {
        Ok(b) => b,
        Err(b) => return b,
    };
    let ixs = match input.instructions {
        Ok(ixs) => ixs,
        Err(why) => {
            return Binding::unbound(format!(
                "the transaction's instructions are not readable ({why}), so its swap cannot be tied to the request"
            ))
        }
    };
    let swaps: Vec<&Ix> = ixs
        .iter()
        .filter(|ix| DECODED_SWAP_PROGRAMS.contains(&ix.program_id.as_str()))
        .collect();
    let ix = match swaps.as_slice() {
        [one] => *one,
        [] => {
            return Binding::unbound(
                "the transaction carries no swap instruction the Core decodes (Jupiter v6 route / shared_accounts_route, Orca Whirlpools, Raydium CLMM, CPMM or AMM v4, Meteora DLMM), so its amounts are not tied to the request",
            )
        }
        many => {
            return Binding::unbound(format!(
                "the transaction carries {} swap instructions; the Core binds a request to one",
                many.len()
            ))
        }
    };
    let decoded = match decode_swap(&ix.program_id, &ix.data) {
        Some(Ok(d)) => d,
        Some(Err(e)) => return Binding::unbound(e),
        None => unreachable!("filtered to decoded programs"),
    };
    let in_decimals = if in_mint == NATIVE_MINT {
        Some(9)
    } else {
        decimals_of(&in_mint, input)
    };
    let Some(in_decimals) = in_decimals else {
        return Binding::unbound(format!(
            "the input mint {in_mint} was not read, so the requested amount cannot be put in base units"
        ));
    };
    let requested = match parse_amount(amount_text, in_decimals) {
        Ok(r) => r,
        Err(e) => return Binding::unbound(e),
    };
    if decoded.amount_in > requested {
        return Binding::mismatch(format!(
            "{} spends {} base units of {in_text}; the request spends {amount_text} ({requested})",
            decoded.name, decoded.amount_in
        ));
    }
    if decoded.min_out == 0 {
        return Binding::Mismatch {
            pattern: SWAP_UNDERBOUNDED,
            reason: format!("{} accepts an output of zero", decoded.name),
        };
    }
    // The effect, from Graphite's own simulation.
    let (Some(diff), Some(wallet)) = (input.diff, input.signers.first()) else {
        return Binding::unbound(
            "no simulated state diff: what the swap spends and delivers was not measured, so neither is tied to the request",
        );
    };
    if let Err(b) = keeps_value(
        decoded.name,
        ixs,
        &[ix],
        input.signers,
        diff,
        &[in_mint.clone(), out_mint.clone()],
    ) {
        return b;
    }
    let effect = wallet_effect(diff, wallet);
    // Round 38 (R37-1): what leaves the wallet is held to what the ROUTE
    // spends, not to the request: a route spending 0.001 of a 1 SOL request
    // beside a transfer of the rest is not a 1 SOL swap.
    if in_mint == NATIVE_MINT {
        if effect.sol_out > i128::from(decoded.amount_in) + SWAP_SOL_OVERHEAD_LAMPORTS as i128 {
            return Binding::mismatch(format!(
                "{} spends {} lamports; the simulation takes {} lamports out of the wallet, more than that plus {SWAP_SOL_OVERHEAD_LAMPORTS} for fees and rent (the request: {amount_text} SOL)",
                decoded.name, decoded.amount_in, effect.sol_out
            ));
        }
    } else {
        let spent = -effect.token_delta.get(&in_mint).copied().unwrap_or(0);
        if spent > i128::from(decoded.amount_in) {
            return Binding::mismatch(format!(
                "{} spends {} base units of {in_mint}; the simulation takes {spent} (the request: {requested})",
                decoded.name, decoded.amount_in
            ));
        }
        if effect.sol_out > SWAP_SOL_OVERHEAD_LAMPORTS as i128 {
            return Binding::mismatch(format!(
                "the request spends {in_mint}, not SOL; the simulation also takes {} lamports out of the wallet",
                effect.sol_out
            ));
        }
    }
    for (mint, delta) in &effect.token_delta {
        if *delta < 0 && mint != &in_mint {
            return Binding::mismatch(format!(
                "the simulation spends {} base units of {mint}, a token the request does not spend",
                -delta
            ));
        }
    }
    let delivered = if out_mint == NATIVE_MINT {
        // SOL may arrive wrapped, or be unwrapped to the wallet beside the
        // route (the signer's own `CloseAccount`, which `keeps_value`
        // allows): every lamport that reached the signer, less the fee.
        effect.wrapped_sol_delta.max(-effect.lamports_out)
    } else {
        effect.token_delta.get(&out_mint).copied().unwrap_or(0)
    };
    if delivered <= 0 {
        return Binding::mismatch(format!(
            "the request asks for {out_text}; the simulation delivers none of it to the wallet's token accounts"
        ));
    }
    if i128::from(decoded.min_out) > delivered {
        return Binding::Mismatch {
            pattern: SWAP_UNDERBOUNDED,
            reason: format!(
                "{}'s minimum output is {}, but the simulation delivered {delivered}",
                decoded.name, decoded.min_out
            ),
        };
    }
    if !within_slippage(decoded.min_out, delivered, bps) {
        return Binding::Mismatch {
            pattern: SWAP_UNDERBOUNDED,
            reason: format!(
                "{}'s minimum output is {}, more than {bps} bps below the {delivered} the simulation delivered: at landing the chain would accept that much less than was verified",
                decoded.name, decoded.min_out
            ),
        };
    }
    Binding::Bound(format!(
        "{} spends {} of the {requested} base units of {in_text} requested and is held by the chain to at least {} of the {delivered} base units of {out_text} simulated ({bps} bps)",
        decoded.name, decoded.amount_in, decoded.min_out
    ))
}

// ── Withdrawals (F-004) ─────────────────────────────────────────────────────

/// What rides beside a withdrawal (Round 38, R37-1): the transaction's
/// top-level instructions, the signers, and the withdrawing program.
pub struct WithdrawalContext<'a> {
    pub instructions: Result<&'a [Ix], &'a str>,
    pub signers: &'a [String],
    pub program_id: &'a str,
}

/// A granted withdrawal's minimum outputs against what the simulation
/// delivered (Round 36, F-004). `minimums` are `(name, value, recipient
/// account)`. A minimum is held to `slippage` of the recipient's simulated
/// token credit; a withdrawal with no minimum the chain enforces is unbound.
///
/// Round 38 (R37-1): the credit is net, so a sibling that moved part of it
/// on left the remainder inside the bound (a CLMM `decrease_liquidity_v2`
/// paying 500 beside a `TransferChecked` of 96 to someone else was
/// `executable_approved` at a minimum of 400). `keeps_value` now holds what
/// rides beside it.
pub fn bind_withdrawal(
    instruction: &str,
    minimums: &[(&str, u64, String)],
    params: Option<&ExtractedParameters>,
    diff: Option<&StateDiff>,
    beside: &WithdrawalContext<'_>,
) -> Binding {
    if minimums.is_empty() {
        return Binding::unbound(format!(
            "{instruction} carries no minimum output the chain enforces: what it pays out at landing is whatever the pool holds then, and nothing ties that to what was simulated"
        ));
    }
    let bps = match slippage(params) {
        Ok(b) => b,
        Err(Binding::Mismatch { reason, .. }) => {
            return Binding::Mismatch {
                pattern: WITHDRAWAL_UNDERBOUNDED,
                reason,
            }
        }
        Err(b) => return b,
    };
    let Some(diff) = diff else {
        return Binding::unbound(format!(
            "no simulated state diff: what {instruction} delivers was not measured, so its minimum outputs cannot be held to it"
        ));
    };
    let ixs = match beside.instructions {
        Ok(ixs) => ixs,
        Err(why) => {
            return Binding::unbound(format!(
                "{instruction}: the transaction's instructions are not readable ({why}), so what rides beside the withdrawal cannot be held"
            ))
        }
    };
    let route: Vec<&Ix> = ixs
        .iter()
        .filter(|ix| ix.program_id == beside.program_id)
        .collect();
    let mints: Vec<String> = minimums
        .iter()
        .filter_map(|(_, _, recipient)| {
            let d = diff.deltas.iter().find(|d| &d.pubkey == recipient)?;
            Some(d.after.as_ref()?.token.as_ref()?.mint.clone())
        })
        .collect();
    if let Err(b) = keeps_value(instruction, ixs, &route, beside.signers, diff, &mints) {
        return match b {
            Binding::Mismatch { reason, .. } => Binding::Mismatch {
                pattern: WITHDRAWAL_UNDERBOUNDED,
                reason,
            },
            other => other,
        };
    }
    let mut held = Vec::new();
    for (name, min, recipient) in minimums {
        let Some(delta) = diff.deltas.iter().find(|d| &d.pubkey == recipient) else {
            return Binding::unbound(format!(
                "{instruction}: the simulation did not observe {recipient}, the account {name} bounds"
            ));
        };
        let before = delta
            .before
            .as_ref()
            .and_then(|s| s.token.as_ref())
            .map(|t| t.amount)
            .unwrap_or(0);
        let Some(after) = delta.after.as_ref().and_then(|s| s.token.as_ref()) else {
            return Binding::unbound(format!(
                "{instruction}: {recipient}, the account {name} bounds, is no token account after the simulation"
            ));
        };
        let delivered = i128::from(after.amount) - i128::from(before);
        if i128::from(*min) > delivered.max(0) {
            return Binding::Mismatch {
                pattern: WITHDRAWAL_UNDERBOUNDED,
                reason: format!(
                    "{instruction}: {name} is {min}, but the simulation delivered {delivered} to {recipient}"
                ),
            };
        }
        if delivered > 0 && !within_slippage(*min, delivered, bps) {
            return Binding::Mismatch {
                pattern: WITHDRAWAL_UNDERBOUNDED,
                reason: format!(
                    "{instruction}: {name} is {min}, more than {bps} bps below the {delivered} the simulation delivered to {recipient}: at landing the chain would accept that much less than was verified"
                ),
            };
        }
        held.push(format!("{name} {min} of {delivered}"));
    }
    Binding::Bound(format!(
        "{instruction}: every minimum output within {bps} bps of what the simulation delivered ({})",
        held.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_are_read_exactly_or_not_at_all() {
        assert_eq!(parse_amount("1", 9), Ok(1_000_000_000));
        assert_eq!(parse_amount("0.000000001", 9), Ok(1));
        assert_eq!(parse_amount("1.5", 6), Ok(1_500_000));
        assert_eq!(parse_amount("18446744073709551615", 0), Ok(u64::MAX));
        for bad in [
            "",
            "0",
            "0.0",
            "-1",
            "+1",
            "1e9",
            "1,5",
            " 1",
            "1 ",
            "1.",
            ".5",
            "1.2.3",
            "0x10",
            "1.0000000001",
            "18446744073709551616000000000",
            "١",
        ] {
            assert!(parse_amount(bad, 9).is_err(), "{bad:?}");
        }
        assert!(parse_amount("1.0000000001", 9).is_err());
        assert!(parse_amount("18446744073709551616", 0).is_err());
    }

    #[test]
    fn jupiter_variant_table_has_every_committed_variant() {
        assert_eq!(JUPITER_SWAP_VARIANTS.len(), 62);
    }
}

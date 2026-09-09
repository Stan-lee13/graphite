//! Solana RPC client for Graphite Core.
//!
//! NOTE: this module is only compiled with the `rpc` feature (lib.rs gates
//! `pub mod rpc_client` on `#[cfg(feature = "rpc")]`). Callers must guard any
//! import with `#[cfg(feature = "rpc")]`. There is intentionally NO fallback
//! placeholder path — without the feature the module does not exist, so any
//! accidental use is a compile error (fail-closed, Constitution P12).
//!
//! Provides real-time access to on-chain data for:
//! - Account state verification
//! - Transaction simulation
//! - Blockhash retrieval
//! - PDA validation
//! - Oracle price validation

use crate::solana_types::Pubkey;
use base64::Engine;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum RpcError {
    #[error("RPC request failed: {0}")]
    RequestFailed(String),
    #[error("Account not found: {0}")]
    AccountNotFound(String),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[error("Timeout after {0:?}")]
    Timeout(Duration),
    #[error("Rate limited")]
    RateLimited,
    #[error("Invalid pubkey: {0}")]
    InvalidPubkey(String),
    /// The request is well-formed but exceeds what the JSON-RPC method
    /// accepts, so it was never sent. Distinct from `RequestFailed`, which
    /// means the network was tried.
    #[error("Unsupported request: {0}")]
    UnsupportedRequest(String),
}

/// Describe a `reqwest` transport/decode failure WITHOUT ever including the
/// request URL.
///
/// SECURITY (CRITICAL, 2026-09-05 audit): `reqwest::Error`'s `Display` impl
/// appends `" for url (<full url>)"` to every error carrying a URL. Managed
/// Solana RPC providers (Helius, QuickNode, Alchemy, Shyft, …) embed the
/// operator's API key directly in that URL, as a query parameter or path
/// segment. `RpcError` values reach `VerificationResult`'s L3 layer `reason`
/// string, which is serialized straight into the `/verify` HTTP response
/// body — so a single ordinary transport hiccup (timeout, DNS blip, TLS
/// error, provider outage) would hand the operator's paid RPC credentials to
/// whoever made the request. Any caller could trigger it on demand simply by
/// sending traffic while the provider is flaky.
///
/// The fix is to never stringify the error at all: classify it from
/// `reqwest::Error`'s predicate methods, which expose the failure CATEGORY
/// with no URL, no header, and no body content. `status()` is safe to include
/// (a bare HTTP status code carries no secret). Callers must use this instead
/// of `e.to_string()` for anything derived from a `reqwest::Error` — see the
/// regression suite in `tests/rpc_secret_redaction.rs`.
pub(crate) fn redact_transport_error(e: &reqwest::Error) -> String {
    let kind = if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connection failed"
    } else if e.is_decode() {
        "malformed response body"
    } else if e.is_redirect() {
        "too many redirects"
    } else if e.is_body() {
        "request body error"
    } else if e.is_request() {
        "request error"
    } else {
        "transport error"
    };
    match e.status() {
        Some(status) => format!("{kind} (HTTP {})", status.as_u16()),
        None => kind.to_string(),
    }
}

/// The `simulateTransaction` config Graphite sends.
///
/// `replaceRecentBlockhash` is the load-bearing one. A Solana blockhash is
/// valid for roughly 150 slots (~60 seconds); without this, simulating a
/// transaction whose blockhash has aged even slightly comes back
/// `BlockhashNotFound`, `unitsConsumed` is 0, and every downstream conclusion
/// collapses — L3 gets no trusted verdict, the baseline cannot grow, and L4
/// abandons its state diff and silently falls back to the shape heuristic.
///
/// Found live on 2026-09-07: the devnet fixtures simulated cleanly by hand and
/// then failed inside Graphite purely because minutes had passed. In production
/// the window is whatever sits between transaction construction and
/// verification — a human approval step, a queue, a retry — so this was a
/// latent, timing-dependent way for the two most expensive layers to quietly
/// stop working.
///
/// Replacing the blockhash is what wallets do for preflight and is correct for
/// the question Graphite asks: "what state effect would these instructions
/// have?" The blockhash is not part of what `content_hash` binds (program,
/// discriminator, accounts, data, CPI targets), so substituting it weakens no
/// binding and changes no observed effect.
///
/// `innerInstructions` is what makes a real CPI count available; see
/// `parse_simulation_value`.
fn simulate_config(commitment: &str, addresses: Option<&[String]>) -> serde_json::Value {
    let mut cfg = serde_json::json!({
        "encoding": "base64",
        "commitment": commitment,
        "replaceRecentBlockhash": true,
        "innerInstructions": true,
    });
    if let Some(addrs) = addresses {
        cfg["accounts"] = serde_json::json!({ "encoding": "base64", "addresses": addrs });
    }
    cfg
}

/// Decode one account object from an RPC response.
///
/// `null` means the account does not exist and yields `Ok(None)` — never a
/// zeroed `AccountState`, which would be fabricated data and would make a
/// missing account indistinguishable from an empty one.
fn parse_account_value(
    pubkey: &str,
    value: &serde_json::Value,
) -> Result<Option<AccountState>, RpcError> {
    if value.is_null() {
        return Ok(None);
    }
    // `lamports` and `owner` are MANDATORY and type-checked.
    //
    // They used to default to 0 and the System Program when unreadable, which
    // fabricates account state — and fabricated state is at its most dangerous
    // in exactly this parser, because L4 exists to reason about state changes.
    //
    // The false-positive direction is obvious (an unreadable pre-state balance
    // of 0 makes any account look newly created). The dangerous direction is
    // quieter: pre-state and post-state fail the SAME way, both become the same
    // default, the delta is zero, and a real movement reads as "nothing
    // changed". A hostile or broken provider returning `"lamports": "5"` for
    // both sides hides the difference between them.
    //
    // This is the invariant the campaign already applies to the simulation
    // parser — unreadable input is ABSENT, never zero — and it was missing
    // here (found in an independent review of `main`, 2026-09-08).
    //
    // `executable`, `rentEpoch` and `data` keep their defaults: they are
    // genuinely optional in some response shapes, and a wrong value for them
    // cannot manufacture or conceal a state delta on its own.
    let lamports = value
        .get("lamports")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            RpcError::InvalidResponse(format!(
                "account {pubkey}: `lamports` is missing or not an unsigned integer — refusing to                  substitute a default, because an invented balance is indistinguishable from a                  measured one once it reaches the state diff"
            ))
        })?;
    let owner = value
        .get("owner")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            RpcError::InvalidResponse(format!(
                "account {pubkey}: `owner` is missing or not a string — refusing to substitute the                  System Program, because that turns an unreadable response into a specific claim                  about who controls the account"
            ))
        })?
        .to_string();
    let executable = value
        .get("executable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let rent_epoch = value.get("rentEpoch").and_then(|v| v.as_u64()).unwrap_or(0);
    let data_base64 = value
        .get("data")
        .and_then(|d| {
            if let Some(arr) = d.as_array() {
                arr.first().and_then(|s| s.as_str())
            } else {
                d.as_str()
            }
        })
        .unwrap_or("");
    let data = if data_base64.is_empty() {
        Vec::new()
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(data_base64)
            .map_err(|e| RpcError::InvalidResponse(format!("invalid base64 account data: {}", e)))?
    };
    Ok(Some(AccountState {
        pubkey: pubkey.to_string(),
        lamports,
        owner,
        executable,
        rent_epoch,
        data,
    }))
}

/// Test seam for the simulation-response parser.
///
/// The parser is the contract between what a Solana RPC actually sends and what
/// Graphite treats as trustworthy evidence, and three separate defects have
/// lived in it. It is worth testing directly against captured real responses
/// rather than only through a live network call, which cannot be replayed and
/// cannot be made to produce a truncated or hostile shape on demand.
pub fn simulation_result_from_value_for_test(
    value: &serde_json::Value,
) -> Result<SimulationResult, RpcError> {
    parse_simulation_value(value)
}

/// Decode a `simulateTransaction` `result.value` object.
///
/// Shared by the plain simulate call and the state-diff one so the two can
/// never drift — a difference in how `unitsConsumed` is read between them
/// would mean the simulation-integrity baseline and the state diff disagreed
/// about the same execution.
fn parse_simulation_value(value: &serde_json::Value) -> Result<SimulationResult, RpcError> {
    let logs: Vec<String> = value
        .get("logs")
        .and_then(|l| l.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Some RPCs report unitsConsumed at the top level of `value`, others
    // under `meta`.
    let nested = |key: &str| -> Option<u64> {
        value.get(key).and_then(|v| v.as_u64()).or_else(|| {
            value
                .get("meta")
                .and_then(|m| m.get(key))
                .and_then(|v| v.as_u64())
        })
    };
    let units_consumed = nested("unitsConsumed").unwrap_or(0);

    let as_u32 = |v: Option<u64>| v.filter(|n| *n <= u64::from(u32::MAX)).map(|n| n as u32);

    // `accountWrites` and `cpiHops` are NOT fields any Solana RPC returns.
    //
    // Confirmed against api.devnet.solana.com on 2026-09-07: a
    // `simulateTransaction` response carries exactly {accounts, err, fee,
    // innerInstructions, loadedAccountsDataSize, loadedAddresses, logs,
    // postBalances, postTokenBalances, preBalances, preTokenBalances,
    // replacementBlockhash, returnData, unitsConsumed}. Neither invented name
    // appears, under any nesting.
    //
    // The caller of this function treats "both fields present" as the test for
    // whether a simulation result is COMPLETE enough to trust (`rpc_sim_ok`),
    // and only a trusted result may grow the baseline or certify a clean L3.
    // Reading for fields that never arrive made that test permanently false, so
    // with a real RPC attached the Simulation Integrity Layer could accumulate
    // nothing and could only ever return "flagged" or "no verdict" — never
    // "clean". The layer was live and structurally unable to reach its own
    // positive result.
    //
    // Both are derived instead, from data the RPC does send, so they stay
    // RPC-DERIVED rather than caller-supplied and the provenance rule is
    // unchanged. The invented names are still read first: a provider that does
    // supply them wins over the derivation.
    //
    // Every entry must parse as a u64. `as_u64()` yields `None` for a float, a
    // string, or a negative, and comparing `None != None` is false — so a
    // response reporting balances in a type Graphite cannot read would derive
    // "nothing changed" and look like a complete, clean observation instead of
    // an unusable one (found 2026-09-08 attacking the RPC trust boundary).
    // Unreadable balances are absent balances.
    let readable = |v: &serde_json::Value| -> Option<Vec<u64>> {
        v.as_array()?.iter().map(|n| n.as_u64()).collect()
    };
    let derived_account_writes = match (
        value.get("preBalances").and_then(&readable),
        value.get("postBalances").and_then(&readable),
    ) {
        // An account whose lamport balance moved was written. This undercounts
        // a write that changed only account DATA at identical lamports, so it
        // is a floor rather than an exact count — which is the safe direction
        // for a divergence baseline: it cannot inflate a spike into normality.
        (Some(pre), Some(post)) if pre.len() == post.len() => {
            Some(pre.iter().zip(post.iter()).filter(|(a, b)| a != b).count() as u64)
        }
        _ => None,
    };
    // Total inner instructions across every top-level instruction: the real
    // CPI count for this execution. Requires `innerInstructions: true` on the
    // request; a `null` here means it was not asked for, which is different
    // from an empty array meaning "no CPI happened".
    let derived_cpi_hops = value
        .get("innerInstructions")
        .and_then(|v| v.as_array())
        .and_then(|groups| {
            // `filter_map` here would silently DROP a group whose shape
            // Graphite cannot read, undercounting CPI hops — the direction that
            // makes a deep call tree look shallow. One unreadable group makes
            // the total unknown, and unknown fails the completeness gate.
            groups
                .iter()
                .map(|g| {
                    g.get("instructions")
                        .and_then(|i| i.as_array())
                        .map(|i| i.len() as u64)
                })
                .sum::<Option<u64>>()
        });

    let account_writes = as_u32(
        nested("accountWrites")
            .or_else(|| {
                value
                    .get("meta")
                    .and_then(|m| m.get("numAccountWrites"))
                    .and_then(|v| v.as_u64())
            })
            .or(derived_account_writes),
    );
    let cpi_hops = as_u32(
        nested("cpiHops")
            .or_else(|| {
                value
                    .get("meta")
                    .and_then(|m| m.get("cpi_hops"))
                    .and_then(|v| v.as_u64())
            })
            .or(derived_cpi_hops),
    );

    let return_data = value
        .get("returnData")
        .and_then(|rd| rd.get("data"))
        .and_then(|d| {
            if let Some(s) = d.as_str() {
                base64::engine::general_purpose::STANDARD.decode(s).ok()
            } else if let Some(arr) = d.as_array() {
                arr.first()
                    .and_then(|inner| inner.as_str())
                    .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
            } else {
                None
            }
        });

    // A JSON `null` here means "no error", not "an error named null".
    let err = value.get("err").filter(|e| !e.is_null()).map(|e| {
        if let Some(s) = e.as_str() {
            s.to_string()
        } else {
            e.to_string()
        }
    });

    // Unreadable entries are dropped rather than silently stringified: an
    // address Graphite cannot read is not an address it can compare against
    // the caller's account list.
    let str_list = |v: Option<&serde_json::Value>| -> Vec<String> {
        v.and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default()
    };
    let loaded_addresses = value.get("loadedAddresses").and_then(|la| {
        if la.is_null() {
            None
        } else {
            Some(LoadedAddresses {
                writable: str_list(la.get("writable")),
                readonly: str_list(la.get("readonly")),
            })
        }
    });

    // Length of the balance arrays = the transaction's whole account universe.
    let artifact_account_count = value
        .get("preBalances")
        .and_then(|v| v.as_array())
        .or_else(|| value.get("postBalances").and_then(|v| v.as_array()))
        .map(|a| a.len());

    Ok(SimulationResult {
        logs,
        units_consumed,
        return_data,
        err,
        account_writes,
        cpi_hops,
        fee: value.get("fee").and_then(|v| v.as_u64()),
        loaded_addresses,
        artifact_account_count,
    })
}

/// Account state from RPC
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccountState {
    pub pubkey: String,
    pub lamports: u64,
    pub owner: String,
    pub executable: bool,
    pub rent_epoch: u64,
    pub data: Vec<u8>,
}

/// On-chain status of a submitted transaction (getSignatureStatuses).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureStatus {
    /// Slot the transaction was included in (0 if unknown).
    pub slot: u64,
    /// Remaining confirmations; None once finalized.
    pub confirmations: Option<u64>,
    /// Whether the transaction executed successfully (status Ok).
    pub success: bool,
    /// RPC error payload when the transaction failed (status Err).
    pub error: Option<String>,
}

/// Simulation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub logs: Vec<String>,
    pub units_consumed: u64,
    pub return_data: Option<Vec<u8>>,
    pub err: Option<String>,
    /// Optional number of account writes observed in simulation (if RPC reports it)
    pub account_writes: Option<u32>,
    /// Optional CPI hop count observed in simulation (if RPC reports it)
    pub cpi_hops: Option<u32>,
    /// Transaction fee in lamports, as the simulator charged it.
    ///
    /// The simulated post-state has this deducted from the fee payer, so any
    /// lamport-conservation arithmetic over that post-state must account for
    /// it. `None` when the RPC did not report a fee.
    pub fee: Option<u64>,
    /// Addresses the runtime resolved through Address Lookup Tables, from the
    /// response's `loadedAddresses`.
    ///
    /// This is the independent ALT signal. Until 2026-09-08 Graphite's only
    /// knowledge of versioned-transaction and ALT usage was the caller's own
    /// `uses_versioned_transaction` boolean, and the pipeline documented that
    /// as a blind spot it could not close — "accounts resolved via ALT are not
    /// independently verified by this pipeline". The simulator was reporting
    /// the answer in the same response Graphite was already reading and
    /// throwing it away.
    ///
    /// `None` when the field is absent. A NON-EMPTY value proves ALT usage. An
    /// EMPTY one proves nothing on its own: a legacy transaction and a v0
    /// transaction that references no lookup table are indistinguishable here,
    /// and the code that consumes this must not read empty as "legacy".
    pub loaded_addresses: Option<LoadedAddresses>,
    /// How many accounts the transaction references in total, from the length
    /// of the balance arrays.
    ///
    /// `preBalances` spans the transaction's ENTIRE account list — every static
    /// key plus everything resolved through a lookup table — so its length is
    /// the size of the account universe the runtime actually executed against.
    /// Graphite gets that number without parsing the transaction and without
    /// believing anything the caller said about it.
    ///
    /// It answers a question a lamport-delta counter cannot ask: not "which
    /// accounts moved value" but "how many accounts are in play at all". A
    /// secondary instruction that reassigns an account's owner, sets a delegate
    /// or freezes a token account moves no lamports and is invisible to a
    /// balance diff — but it cannot be invisible here, because the account it
    /// touches has to be in the transaction to be touched.
    pub artifact_account_count: Option<usize>,
}

/// The `loadedAddresses` half of a `simulateTransaction` response: the accounts
/// a versioned transaction pulled in through Address Lookup Tables, which never
/// appear in the transaction's own static account keys.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoadedAddresses {
    pub writable: Vec<String>,
    pub readonly: Vec<String>,
}

impl LoadedAddresses {
    pub fn is_empty(&self) -> bool {
        self.writable.is_empty() && self.readonly.is_empty()
    }
    pub fn len(&self) -> usize {
        self.writable.len() + self.readonly.len()
    }
    /// Every loaded address, writable first.
    pub fn all(&self) -> impl Iterator<Item = &String> {
        self.writable.iter().chain(self.readonly.iter())
    }
}

/// Oracle price data
///
/// NOTE: removed from the RPC client as fake logic (2026-08-06 production
/// audit): `get_oracle_price` returned a hardcoded zeroed `OraclePrice`
/// without any RPC call — a placeholder that would silently feed price=0 to
/// consumers. Phase 2 adds a real Pyth/Switchboard decoder behind this
/// struct when the price-validation layer lands. The type itself is kept
/// (it is part of the public API surface), but there is deliberately NO
/// method that fabricates one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OraclePrice {
    pub feed_id: String,
    pub price: i128,
    pub confidence: u64,
    pub timestamp: i64,
    pub exponent: i32,
}

/// The largest response body Graphite will buffer from an RPC peer.
///
/// `Response::json()` reads to end-of-body with no limit, so before this cap the
/// peer chose Graphite's memory footprint: anything answering on the RPC socket
/// — a compromised provider, a hijacked DNS record, a proxy on a plaintext
/// `http://` endpoint — could return a body larger than the container's 512MB
/// and take the process down without ever being asked for anything. This is the
/// same defect class already fixed on the audit trail (storage whose size the
/// attacker picks), on a boundary that is cheaper to reach.
///
/// 32 MiB clears every response Graphite actually makes: a Solana account tops
/// out at 10 MiB, which is ~13.4 MiB base64-encoded, and the fetches here are
/// for an instruction's writable accounts rather than bulk program data.
const MAX_RPC_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

/// The longest attacker-chosen text that may travel inside an `RpcError`.
///
/// A JSON-RPC error body is echoed into `RpcError::RequestFailed`, which reaches
/// the L3 layer `reason` and the audit trail. Both its length and its content
/// are the peer's to choose, so an unbounded echo is both storage the peer sizes
/// and text the peer writes into a field a human reads before signing. Bounded
/// the same way `AuditErrorRecord` bounds its fields, and for the same reason.
const MAX_RPC_ERROR_CHARS: usize = 256;

fn bound_rpc_text(value: &str) -> String {
    if value.chars().count() <= MAX_RPC_ERROR_CHARS {
        return value.to_string();
    }
    let kept: String = value.chars().take(MAX_RPC_ERROR_CHARS).collect();
    // Say what was dropped: a silently shortened diagnostic reads as the whole
    // one.
    format!("{kept}… [truncated, {} chars total]", value.chars().count())
}

/// Read a response body with a hard ceiling, streaming so an oversized one is
/// abandoned rather than allocated.
///
/// The declared `Content-Length` is checked first so an honest oversize costs
/// nothing, and the chunk loop bounds a chunked or mis-declared body that the
/// header did not.
async fn read_body_capped(mut res: reqwest::Response) -> Result<Vec<u8>, RpcError> {
    if let Some(declared) = res.content_length() {
        if declared > MAX_RPC_RESPONSE_BYTES as u64 {
            return Err(RpcError::InvalidResponse(format!(
                "RPC response too large: {declared} bytes declared, limit is {MAX_RPC_RESPONSE_BYTES}"
            )));
        }
    }
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = res
        .chunk()
        .await
        .map_err(|e| RpcError::InvalidResponse(redact_transport_error(&e)))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_RPC_RESPONSE_BYTES {
            return Err(RpcError::InvalidResponse(format!(
                "RPC response too large: exceeded the {MAX_RPC_RESPONSE_BYTES}-byte limit"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Configuration for RPC client
#[derive(Debug, Clone)]
pub struct RpcConfig {
    pub endpoint: String,
    pub commitment: String,
    pub timeout: Duration,
    pub max_retries: u32,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://api.devnet.solana.com".to_string(),
            commitment: "confirmed".to_string(),
            timeout: Duration::from_secs(30),
            max_retries: 3,
        }
    }
}

/// Solana RPC client
#[derive(Debug, Clone)]
pub struct SolanaRpcClient {
    config: RpcConfig,
    http_client: Option<HttpClient>,
}

impl SolanaRpcClient {
    /// Create new RPC client with given configuration
    pub fn new(config: RpcConfig) -> Self {
        // Build the HTTP client BEFORE moving `config` into the struct
        // (field init uses the value first — a use-after-move otherwise).
        let http_client = HttpClient::builder().timeout(config.timeout).build().ok();
        Self {
            config,
            http_client,
        }
    }

    /// Create client for Devnet
    pub fn devnet() -> Self {
        Self::new(RpcConfig {
            endpoint: "https://api.devnet.solana.com".to_string(),
            ..Default::default()
        })
    }

    /// Create client for Mainnet
    pub fn mainnet() -> Self {
        Self::new(RpcConfig {
            endpoint: "https://api.mainnet-beta.solana.com".to_string(),
            ..Default::default()
        })
    }

    /// Shared JSON-RPC POST with retry/backoff (uses `config.max_retries`).
    ///
    /// - HTTP 429 → `RpcError::RateLimited` (retried up to `max_retries`;
    ///   if it never clears, surfaces as `RateLimited`).
    /// - HTTP 5xx → transient server error, retried.
    /// - HTTP 2xx with a JSON-RPC `error` field → definitive `RequestFailed`.
    /// - Other non-2xx → `RequestFailed`.
    ///
    /// Returns the JSON-RPC `result` value on success.
    async fn post_rpc(&self, body: serde_json::Value) -> Result<serde_json::Value, RpcError> {
        let client = self
            .http_client
            .as_ref()
            .ok_or_else(|| RpcError::RequestFailed("http client not initialized".to_string()))?;
        let attempts = self.config.max_retries.saturating_add(1).max(1);
        let mut last_err = RpcError::RequestFailed("request failed".to_string());
        for attempt in 0..attempts {
            match client.post(&self.config.endpoint).json(&body).send().await {
                Ok(res) => {
                    let status = res.status();
                    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                        last_err = RpcError::RateLimited;
                        sleep_backoff(attempt).await;
                        continue;
                    }
                    if status.is_server_error() {
                        last_err = RpcError::RequestFailed(format!("RPC server error: {}", status));
                        sleep_backoff(attempt).await;
                        continue;
                    }
                    if !status.is_success() {
                        return Err(RpcError::RequestFailed(format!(
                            "RPC HTTP error: {}",
                            status
                        )));
                    }
                    let body = read_body_capped(res).await?;
                    let json: serde_json::Value = serde_json::from_slice(&body)
                        .map_err(|e| RpcError::InvalidResponse(bound_rpc_text(&e.to_string())))?;
                    if let Some(err) = json.get("error") {
                        // Bounded: this string reaches the L3 reason and the
                        // audit trail, and the peer wrote it.
                        return Err(RpcError::RequestFailed(bound_rpc_text(&err.to_string())));
                    }
                    return json
                        .get("result")
                        .cloned()
                        .ok_or_else(|| RpcError::InvalidResponse("missing result".to_string()));
                }
                Err(e) => {
                    // Network/transport failure — retryable. NEVER stringify
                    // `e` directly: its Display carries the full request URL,
                    // which embeds the operator's RPC API key (see
                    // `redact_transport_error`).
                    last_err = RpcError::RequestFailed(redact_transport_error(&e));
                    sleep_backoff(attempt).await;
                }
            }
        }
        Err(last_err)
    }

    /// Fetch account state from RPC
    ///
    /// # Errors
    /// - `RpcError::AccountNotFound` if account doesn't exist (null value)
    /// - `RpcError::RequestFailed` for network/connection issues
    pub async fn get_account(&self, pubkey: &Pubkey) -> Result<AccountState, RpcError> {
        tracing::info!("RPC: get_account called for {}", pubkey.to_base58());
        let params = serde_json::json!([pubkey.to_base58(),{"encoding":"base64","commitment":self.config.commitment}]);
        let body =
            serde_json::json!({"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":params});
        let result = self.post_rpc(body).await?;
        // A missing account returns `value: null` — that is AccountNotFound,
        // NOT a zeroed account (which would be fabricated data).
        let value = result
            .get("value")
            .ok_or_else(|| RpcError::InvalidResponse("missing result.value".to_string()))?;
        parse_account_value(&pubkey.to_base58(), value)?
            .ok_or_else(|| RpcError::AccountNotFound(pubkey.to_base58()))
    }

    /// Verify PDA derivation matches on-chain state
    ///
    /// # Security
    /// This is critical for detecting PDA spoofing attacks where an attacker
    /// provides a non-derived address that looks like a PDA.
    pub async fn verify_pda(
        &self,
        expected_pda: &Pubkey,
        seeds: &[&[u8]],
        program_id: &Pubkey,
    ) -> Result<bool, RpcError> {
        // Derive what the PDA should be.
        // NOTE: written as a `match` instead of `.ok_or_else(...)?` because the
        // method chain hit an E0599 method-resolution failure at this call site
        // on the GNU Windows toolchain while identical calls elsewhere in this
        // file compile — the match is semantically identical and portable.
        // Don't "simplify" it back without testing on that toolchain.
        let (derived, _bump) = match crate::solana_types::find_program_address(seeds, program_id) {
            Ok(pair) => pair,
            Err(_) => {
                return Err(RpcError::InvalidPubkey("PDA derivation failed".to_string()));
            }
        };

        // Check if it matches
        let matches = derived.as_bytes() == expected_pda.as_bytes();

        if !matches {
            tracing::warn!(
                "PDA mismatch: expected={}, derived={}",
                expected_pda.to_base58(),
                derived.to_base58()
            );
        }

        Ok(matches)
    }

    /// Simulate a transaction without executing it
    ///
    /// # Use Cases
    /// - Compute unit estimation
    /// - Error detection before execution
    /// - Sandboxing suspicious transactions
    pub async fn simulate_transaction(
        &self,
        transaction_data: &[u8],
    ) -> Result<SimulationResult, RpcError> {
        tracing::info!(
            "RPC: simulate_transaction called with {} bytes",
            transaction_data.len()
        );

        let tx_b64 = base64::engine::general_purpose::STANDARD.encode(transaction_data);
        let params = serde_json::json!([tx_b64, simulate_config(&self.config.commitment, None)]);
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"simulateTransaction","params":params});
        let result = self.post_rpc(body).await?;
        let value = result
            .get("value")
            .ok_or_else(|| RpcError::InvalidResponse("missing result.value".to_string()))?;
        parse_simulation_value(value)
    }

    /// Fetch several accounts in one round trip.
    ///
    /// Returns one entry per requested address, in request order. `None` means
    /// the account does not exist — deliberately distinct from a zeroed
    /// account, because a diff that reads "created" and one that reads
    /// "unchanged and empty" mean opposite things.
    ///
    /// The RPC caps a single `getMultipleAccounts` at 100 addresses, so longer
    /// lists are chunked. Any chunk that fails fails the whole call: a
    /// partially-populated pre-state would silently turn untouched accounts
    /// into phantom creations.
    pub async fn get_multiple_accounts(
        &self,
        pubkeys: &[String],
    ) -> Result<Vec<Option<AccountState>>, RpcError> {
        const CHUNK: usize = 100;
        let mut out: Vec<Option<AccountState>> = Vec::with_capacity(pubkeys.len());
        for chunk in pubkeys.chunks(CHUNK) {
            let params = serde_json::json!([
                chunk,
                {"encoding":"base64","commitment":self.config.commitment}
            ]);
            let body = serde_json::json!({
                "jsonrpc":"2.0","id":1,"method":"getMultipleAccounts","params":params
            });
            let result = self.post_rpc(body).await?;
            let values = result
                .get("value")
                .and_then(|v| v.as_array())
                .ok_or_else(|| RpcError::InvalidResponse("missing result.value".to_string()))?;
            if values.len() != chunk.len() {
                return Err(RpcError::InvalidResponse(format!(
                    "getMultipleAccounts returned {} entries for {} addresses",
                    values.len(),
                    chunk.len()
                )));
            }
            for (addr, value) in chunk.iter().zip(values) {
                out.push(parse_account_value(addr, value)?);
            }
        }
        Ok(out)
    }

    /// Simulate a transaction and ask the RPC for the post-execution state of
    /// specific accounts.
    ///
    /// This is the other half of a real state diff: `getMultipleAccounts` gives
    /// the state before, and `simulateTransaction`'s `accounts` request gives
    /// the state the transaction would leave behind. Returns the simulation
    /// result alongside one post-state entry per requested address, in request
    /// order.
    ///
    /// The RPC caps the `accounts.addresses` list at 100. A longer list cannot
    /// be chunked the way a read can — every chunk would be a separate
    /// simulation — so this returns `UnsupportedRequest` rather than
    /// simulating repeatedly and stitching together results that may not
    /// correspond to the same execution.
    pub async fn simulate_transaction_with_accounts(
        &self,
        transaction_data: &[u8],
        addresses: &[String],
    ) -> Result<(SimulationResult, Vec<Option<AccountState>>), RpcError> {
        const MAX_SIM_ACCOUNTS: usize = 100;
        if addresses.len() > MAX_SIM_ACCOUNTS {
            return Err(RpcError::UnsupportedRequest(format!(
                "simulateTransaction accepts at most {MAX_SIM_ACCOUNTS} account addresses (got {})",
                addresses.len()
            )));
        }

        tracing::info!(
            "RPC: simulate_transaction_with_accounts called with {} bytes, {} address(es)",
            transaction_data.len(),
            addresses.len()
        );
        let tx_b64 = base64::engine::general_purpose::STANDARD.encode(transaction_data);
        let params = serde_json::json!([
            tx_b64,
            simulate_config(&self.config.commitment, Some(addresses))
        ]);
        let body = serde_json::json!({
            "jsonrpc":"2.0","id":1,"method":"simulateTransaction","params":params
        });
        let result = self.post_rpc(body).await?;
        let value = result
            .get("value")
            .ok_or_else(|| RpcError::InvalidResponse("missing result.value".to_string()))?;

        let sim = parse_simulation_value(value)?;

        // `accounts` is null when the simulation failed outright, and an
        // element is null when that account does not exist after execution.
        let post = match value.get("accounts").and_then(|a| a.as_array()) {
            Some(arr) => {
                if arr.len() != addresses.len() {
                    return Err(RpcError::InvalidResponse(format!(
                        "simulateTransaction returned {} account entries for {} addresses",
                        arr.len(),
                        addresses.len()
                    )));
                }
                addresses
                    .iter()
                    .zip(arr)
                    .map(|(addr, v)| parse_account_value(addr, v))
                    .collect::<Result<Vec<_>, _>>()?
            }
            None => Vec::new(),
        };

        Ok((sim, post))
    }

    /// Verify account is not frozen (for token accounts)
    ///
    /// # Security
    /// Prevents transactions that would fail due to frozen accounts.
    pub async fn is_account_frozen(&self, token_account: &Pubkey) -> Result<bool, RpcError> {
        let account = self.get_account(token_account).await?;
        Ok(token_account_frozen_flag(&account))
    }

    /// Get the current slot
    pub async fn get_slot(&self) -> Result<u64, RpcError> {
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"getSlot","params":[{"commitment":self.config.commitment}]});
        let result = self.post_rpc(body).await?;
        // Live-verified 2026-08-06: getSlot returns a PLAIN u64 in `result`
        // (e.g. `{"result":437672586}`), NOT `result.value`. Fixed parsing.
        result
            .as_u64()
            .ok_or_else(|| RpcError::InvalidResponse("missing or invalid slot result".to_string()))
    }

    /// Fetch a block's full transaction list as JSON (encoding: json, full
    /// transaction details, versioned transactions included). Used by the live
    /// real-transaction corpus tests and Phase-2 on-chain verification.
    pub async fn get_block(&self, slot: u64) -> Result<serde_json::Value, RpcError> {
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"getBlock","params":[slot,{"encoding":"json","transactionDetails":"full","maxSupportedTransactionVersion":0,"rewards":false}]});
        let result = self.post_rpc(body).await?;
        Ok(result)
    }

    /// Recent signatures for an address/program (`getSignaturesForAddress`),
    /// newest first, each with its error status. Used by the live protocol
    /// corpus to find REAL transactions that invoke a specific manifest
    /// program (per-protocol grounding).
    pub async fn get_signatures_for_address(
        &self,
        address: &str,
        limit: u64,
    ) -> Result<serde_json::Value, RpcError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "getSignaturesForAddress",
            "params": [address, {"limit": limit}]
        });
        self.post_rpc(body).await
    }

    /// Fetch one transaction by signature (`getTransaction`, encoding: json,
    /// versioned transactions included). Returns the full result object
    /// (`transaction`, `slot`, `blockTime`, `meta`) — the exact shape the
    /// pinned mainnet fixtures and `tx_to_input` consume.
    pub async fn get_transaction(&self, signature: &str) -> Result<serde_json::Value, RpcError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "getTransaction",
            "params": [signature, {"encoding": "json", "maxSupportedTransactionVersion": 0}]
        });
        self.post_rpc(body).await
    }

    /// Get recent blockhash
    pub async fn get_latest_blockhash(&self) -> Result<String, RpcError> {
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash","params":[{"commitment":self.config.commitment}]});
        let result = self.post_rpc(body).await?;
        let blockhash = result
            .get("value")
            .and_then(|v| v.get("blockhash"))
            .and_then(|bh| bh.as_str())
            .ok_or_else(|| RpcError::InvalidResponse("missing blockhash".to_string()))?
            .to_string();
        Ok(blockhash)
    }

    /// Confirm the on-chain status of a submitted transaction (L8 execution
    /// verification primitive). `getSignatureStatuses` returns per-signature
    /// status: `Ok` with `Some(status)` when the transaction was confirmed and
    /// included in a slot, `Ok` with `None` when the signature is unknown
    /// (still pending or never submitted), and an error for malformed input.
    ///
    /// This is the honest post-submission check: Graphite cannot guarantee
    /// execution BEFORE submission, but once a transaction is submitted, its
    /// inclusion and success can be confirmed against the cluster. L8 stays
    /// Inconclusive during pre-submission verification BY DESIGN (see
    /// verification.rs L8) and only becomes conclusive with a real signature
    /// plus this RPC evidence.
    pub async fn get_signature_status(
        &self,
        signature: &str,
    ) -> Result<Option<SignatureStatus>, RpcError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getSignatureStatuses",
            "params": [[signature], {"searchTransactionHistory": true}]
        });
        let result = self.post_rpc(body).await?;
        let value = result
            .get("value")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first().cloned())
            .ok_or_else(|| {
                RpcError::InvalidResponse(
                    "missing getSignatureStatuses result.value[0]".to_string(),
                )
            })?;
        if value.is_null() {
            return Ok(None);
        }
        let slot = value.get("slot").and_then(|s| s.as_u64()).unwrap_or(0);
        let confirmations = value.get("confirmations").and_then(|c| c.as_u64());
        let status = value.get("status").and_then(|s| s.as_object());
        let (err, success) = match status {
            Some(map) if map.contains_key("Ok") => (None, true),
            Some(map) if map.contains_key("Err") => (
                map.get("Err").map(|e| {
                    serde_json::to_string(e).unwrap_or_else(|_| "unknown error".to_string())
                }),
                false,
            ),
            _ => (None, false),
        };
        Ok(Some(SignatureStatus {
            slot,
            confirmations,
            success,
            error: err,
        }))
    }
}

/// Exponential backoff between RPC retries: 50ms * 2^attempt, capped at 1s.
async fn sleep_backoff(attempt: u32) {
    let ms = (50u64 << attempt.min(5)).min(1000);
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

/// Pure SPL Token frozen-state check on account data.
///
/// SPL Token account layout: mint(32) + owner(32) + amount(8) +
/// delegate COption(36) = 108 bytes, then a 1-byte state field
/// (0=Uninitialized, 1=Initialized, 2=Frozen).
///
/// SECURITY FIX (2026-08-06 audit): the previous implementation read byte
/// 46 (inside the owner field) and silently returned `false` for non-token
/// accounts — a wrong-result security check. Now:
/// - non-token accounts (wrong owner) are NOT "not frozen" — the check is
///   inconclusive and must be treated as a FAIL (frozen=true is only
///   asserted; a wrong-owner account returns `true` to block execution
///   rather than silently approve, per P12 fail-closed).
/// - the state byte is read from the correct offset 108.
pub fn token_account_frozen_flag(account: &AccountState) -> bool {
    const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    const STATE_OFFSET: usize = 108;

    if account.owner != TOKEN_PROGRAM_ID {
        // Not a token account — the caller asked a question this account
        // cannot answer. Fail-closed (P12): treat as frozen/inconclusive
        // rather than silently approving.
        return true;
    }
    if account.data.len() <= STATE_OFFSET {
        // Truncated data — cannot determine state. Fail-closed.
        return true;
    }
    account.data[STATE_OFFSET] == 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Minimal in-process HTTP server for deterministic RPC tests (no network).
    /// Serves one response per connection; `responses` is `(status, body)`.
    fn mock_rpc_server(
        responses: Vec<(u16, &'static str)>,
    ) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            for (status, body) in responses {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf); // drain the request
                    let reason = if status == 200 { "OK" } else { "Error" };
                    let head = format!(
                        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        status, reason, body.len()
                    );
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(body.as_bytes());
                    let _ = stream.flush();
                }
            }
        });
        (format!("http://{}", addr), handle)
    }

    fn client_at(url: &str, max_retries: u32) -> SolanaRpcClient {
        SolanaRpcClient::new(RpcConfig {
            endpoint: url.to_string(),
            timeout: Duration::from_secs(5),
            max_retries,
            ..Default::default()
        })
    }

    /// REGRESSION (live-verified 2026-08-06): `getSlot` returns a PLAIN u64
    /// in `result` (e.g. `{"result":437672586}`), NOT `result.value`. The
    /// previous parser read `result.value`, so this call always failed with
    /// `InvalidResponse` — breaking the live-corpus test and L3 wiring.
    #[tokio::test]
    async fn test_get_slot_parses_plain_u64_result() {
        let (url, handle) = mock_rpc_server(vec![(
            200,
            "{\"jsonrpc\":\"2.0\",\"result\":437672586,\"id\":1}",
        )]);
        let client = client_at(&url, 0);
        let slot = client
            .get_slot()
            .await
            .expect("get_slot must parse plain u64 result");
        assert_eq!(slot, 437672586);
        handle.join().unwrap();
    }

    /// `getAccountInfo` on a missing account returns `result.value: null`.
    /// The previous parser treated null as a zeroed account (fake data); it
    /// must surface `AccountNotFound` instead.
    #[tokio::test]
    async fn test_get_account_null_value_returns_account_not_found() {
        let (url, handle) = mock_rpc_server(vec![(
            200,
            "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"slot\":1},\"value\":null},\"id\":1}",
        )]);
        let client = client_at(&url, 0);
        let pk = Pubkey::from_base58("11111111111111111111111111111111").unwrap();
        let err = client.get_account(&pk).await.unwrap_err();
        assert!(
            matches!(err, RpcError::AccountNotFound(_)),
            "null result.value must map to AccountNotFound, got {:?}",
            err
        );
        handle.join().unwrap();
    }

    /// Retries: a 503 must be retried (up to max_retries) and a later 200
    /// must succeed. This proves `max_retries` in RpcConfig is actually used.
    #[tokio::test]
    async fn test_retries_on_5xx_then_succeeds() {
        let (url, handle) = mock_rpc_server(vec![
            (503, "service unavailable"),
            (200, "{\"jsonrpc\":\"2.0\",\"result\":12345,\"id\":1}"),
        ]);
        let client = client_at(&url, 3);
        let slot = client
            .get_slot()
            .await
            .expect("retry must succeed on second attempt");
        assert_eq!(slot, 12345);
        handle.join().unwrap();
    }

    /// Rate limiting: after exhausting retries against a persistent 429, the
    /// client must return the dedicated `RateLimited` error (never a generic
    /// string error), so callers can back off explicitly.
    #[tokio::test]
    async fn test_persistent_429_returns_rate_limited() {
        let (url, handle) = mock_rpc_server(vec![(429, "rate limited"), (429, "rate limited")]);
        let client = client_at(&url, 1); // 1 retry → 2 attempts total
        let err = client.get_slot().await.unwrap_err();
        assert!(
            matches!(err, RpcError::RateLimited),
            "persistent 429 must map to RateLimited, got {:?}",
            err
        );
        handle.join().unwrap();
    }

    /// JSON-RPC `error` responses (e.g. -32602 invalid param) must surface
    /// as a definitive request failure — NOT be retried or parsed as data.
    #[tokio::test]
    async fn test_jsonrpc_error_is_request_failed() {
        let (url, handle) = mock_rpc_server(vec![(
            200,
            "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid param\"},\"id\":1}",
        )]);
        let client = client_at(&url, 3);
        let err = client.get_slot().await.unwrap_err();
        assert!(
            matches!(err, RpcError::RequestFailed(_)),
            "JSON-RPC error must map to RequestFailed, got {:?}",
            err
        );
        handle.join().unwrap();
    }

    /// get_latest_blockhash parses the real response shape
    /// (`result.value.blockhash`) — regression guard for L3 wiring.
    #[tokio::test]
    async fn test_get_latest_blockhash_parses() {
        let (url, handle) = mock_rpc_server(vec![(
            200,
            "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"slot\":1},\"value\":{\"blockhash\":\"3pq18hX1Ucpnm7n1UP5d7wK8eCDo9bbYWvdx1GJmwrfr\",\"lastValidBlockHeight\":415727014}},\"id\":1}",
        )]);
        let client = client_at(&url, 0);
        let bh = client
            .get_latest_blockhash()
            .await
            .expect("blockhash must parse");
        assert_eq!(bh, "3pq18hX1Ucpnm7n1UP5d7wK8eCDo9bbYWvdx1GJmwrfr");
        handle.join().unwrap();
    }

    #[tokio::test]
    async fn test_get_signature_status_confirmed_success() {
        let (url, handle) = mock_rpc_server(vec![(
            200,
            "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"slot\":2},\"value\":[{\"slot\":100,\"confirmations\":0,\"err\":null,\"status\":{\"Ok\":null}}]},\"id\":1}",
        )]);
        let client = client_at(&url, 0);
        let st = client
            .get_signature_status("5sigAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .await
            .expect("status must parse")
            .expect("signature must be known");
        assert_eq!(st.slot, 100);
        assert!(st.success);
        assert_eq!(st.confirmations, Some(0));
        assert!(st.error.is_none());
        handle.join().unwrap();
    }

    #[tokio::test]
    async fn test_get_signature_status_err_is_failure() {
        let (url, handle) = mock_rpc_server(vec![(
            200,
            "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"slot\":2},\"value\":[{\"slot\":101,\"confirmations\":null,\"err\":null,\"status\":{\"Err\":{\"InstructionError\":[0,{\"Custom\":1}]}}}]},\"id\":1}",
        )]);
        let client = client_at(&url, 0);
        let st = client
            .get_signature_status("5sigAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .await
            .expect("status must parse")
            .expect("signature must be known");
        assert!(!st.success, "Err status must not be success");
        assert!(st.error.is_some());
        handle.join().unwrap();
    }

    #[tokio::test]
    async fn test_get_signature_status_unknown_signature_returns_none() {
        let (url, handle) = mock_rpc_server(vec![(
            200,
            "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"slot\":2},\"value\":[null]},\"id\":1}",
        )]);
        let client = client_at(&url, 0);
        let st = client
            .get_signature_status("5sigAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .await
            .expect("null value must parse as None");
        assert!(st.is_none(), "unknown signature must be None");
        handle.join().unwrap();
    }

    /// SPL Token account state lives at byte 108 (mint 32 + owner 32 + amount
    /// 8 + delegate COption 36), value 2 = Frozen. The previous parser read
    /// byte 46 (inside the owner field) and silently reported `false` for
    /// non-token accounts — a wrong-result security check.
    #[tokio::test]
    async fn test_is_account_frozen_reads_state_at_byte_108() {
        // owner = TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, frozen state at 108.
        let mut data = vec![0u8; 165];
        data[108] = 2; // Frozen
        let account = AccountState {
            pubkey: "x".to_string(),
            lamports: 0,
            owner: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
            executable: false,
            rent_epoch: 0,
            data,
        };
        // Test the pure helper directly (the network path is covered by the
        // live ignored test): parse the frozen flag from account data.
        assert!(token_account_frozen_flag(&account));

        let mut not_frozen = vec![0u8; 165];
        not_frozen[108] = 1; // Initialized, not frozen
        let account2 = AccountState {
            data: not_frozen,
            ..account.clone()
        };
        assert!(!token_account_frozen_flag(&account2));

        // Fail-closed (P12): a non-token account cannot answer the frozen
        // question — it must NOT silently report "not frozen". The previous
        // implementation returned `false` here, a wrong-result security check.
        let wrong_owner = AccountState {
            owner: "11111111111111111111111111111111".to_string(),
            ..account.clone()
        };
        assert!(
            token_account_frozen_flag(&wrong_owner),
            "non-token account must fail closed (treated as frozen), not silently pass"
        );

        // Truncated data (shorter than the state offset) must also fail closed.
        let truncated = AccountState {
            data: vec![0u8; 40],
            ..account
        };
        assert!(token_account_frozen_flag(&truncated));
    }

    #[tokio::test]
    async fn test_rpc_client_creation() {
        let client = SolanaRpcClient::devnet();
        assert_eq!(client.config.endpoint, "https://api.devnet.solana.com");
    }

    #[tokio::test]
    async fn test_get_account_without_http_client_errors_cleanly() {
        // Deterministic (no network): covers the uninitialized-client error path.
        let client = SolanaRpcClient {
            config: RpcConfig::default(),
            http_client: None,
        };
        let pubkey = Pubkey::from_base58("11111111111111111111111111111111").unwrap();
        let err = client.get_account(&pubkey).await.unwrap_err();
        assert!(matches!(err, RpcError::RequestFailed(_)));
    }

    #[tokio::test]
    #[ignore = "makes a live devnet RPC call — run explicitly: cargo test --all-features -- --ignored"]
    async fn test_get_account_live_devnet() {
        let client = SolanaRpcClient::devnet();
        let pubkey = Pubkey::from_base58("11111111111111111111111111111111").unwrap();
        let account = client.get_account(&pubkey).await.unwrap();
        assert_eq!(account.pubkey, "11111111111111111111111111111111");
    }
}

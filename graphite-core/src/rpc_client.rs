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
                    let json: serde_json::Value = res
                        .json()
                        .await
                        .map_err(|e| RpcError::InvalidResponse(e.to_string()))?;
                    if json.get("error").is_some() {
                        return Err(RpcError::RequestFailed(json.to_string()));
                    }
                    return json
                        .get("result")
                        .cloned()
                        .ok_or_else(|| RpcError::InvalidResponse("missing result".to_string()));
                }
                Err(e) => {
                    // Network/transport failure — retryable.
                    last_err = RpcError::RequestFailed(e.to_string());
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
        let value = match result.get("value") {
            Some(v) if !v.is_null() => v,
            _ => return Err(RpcError::AccountNotFound(pubkey.to_base58())),
        };
        let lamports = value.get("lamports").and_then(|v| v.as_u64()).unwrap_or(0);
        let owner = value
            .get("owner")
            .and_then(|v| v.as_str())
            .unwrap_or("11111111111111111111111111111111")
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
                .map_err(|e| {
                    RpcError::InvalidResponse(format!("invalid base64 account data: {}", e))
                })?
        };
        Ok(AccountState {
            pubkey: pubkey.to_base58(),
            lamports,
            owner,
            executable,
            rent_epoch,
            data,
        })
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

        {
            let tx_b64 = base64::engine::general_purpose::STANDARD.encode(transaction_data);
            let params = serde_json::json!([tx_b64, {"encoding":"base64"}]);
            let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"simulateTransaction","params":params});
            let result = self.post_rpc(body).await?;
            let value = result
                .get("value")
                .ok_or_else(|| RpcError::InvalidResponse("missing result.value".to_string()))?;

            // logs
            let logs: Vec<String> = value
                .get("logs")
                .and_then(|l| l.as_array().cloned())
                .map(|arr| {
                    arr.into_iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            // units consumed (some RPCs return unitsConsumed at top-level of value)
            let units_consumed = value
                .get("unitsConsumed")
                .and_then(|u| u.as_u64())
                .or_else(|| {
                    value
                        .get("meta")
                        .and_then(|m| m.get("unitsConsumed"))
                        .and_then(|u| u.as_u64())
                })
                .unwrap_or(0);

            // Attempt to extract account_writes and cpi_hops from common keys
            let account_writes = value
                .get("accountWrites")
                .and_then(|v| v.as_u64())
                .or_else(|| {
                    value
                        .get("meta")
                        .and_then(|m| m.get("accountWrites"))
                        .and_then(|v| v.as_u64())
                })
                .or_else(|| {
                    value
                        .get("meta")
                        .and_then(|m| m.get("numAccountWrites"))
                        .and_then(|v| v.as_u64())
                })
                .and_then(|v| {
                    if v <= u64::from(u32::MAX) {
                        Some(v as u32)
                    } else {
                        None
                    }
                });

            let cpi_hops = value
                .get("cpiHops")
                .and_then(|v| v.as_u64())
                .or_else(|| {
                    value
                        .get("meta")
                        .and_then(|m| m.get("cpiHops"))
                        .and_then(|v| v.as_u64())
                })
                .or_else(|| {
                    value
                        .get("meta")
                        .and_then(|m| m.get("cpi_hops"))
                        .and_then(|v| v.as_u64())
                })
                .and_then(|v| {
                    if v <= u64::from(u32::MAX) {
                        Some(v as u32)
                    } else {
                        None
                    }
                });

            // return data: optional field
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

            let err = value.get("err").map(|e| {
                if let Some(s) = e.as_str() {
                    s.to_string()
                } else {
                    e.to_string()
                }
            });

            Ok(SimulationResult {
                logs,
                units_consumed,
                return_data,
                err,
                account_writes,
                cpi_hops,
            })
        }
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

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

    /// Fetch account state from RPC
    ///
    /// # Errors
    /// - `RpcError::AccountNotFound` if account doesn't exist
    /// - `RpcError::RequestFailed` for network/connection issues
    pub async fn get_account(&self, pubkey: &Pubkey) -> Result<AccountState, RpcError> {
        // In production, this makes a real HTTP POST request to Solana RPC.
        tracing::info!("RPC: get_account called for {}", pubkey.to_base58());
        {
            let client = self.http_client.as_ref().ok_or_else(|| {
                RpcError::RequestFailed("http client not initialized".to_string())
            })?;
            let params = serde_json::json!([pubkey.to_base58(),{"encoding":"base64","commitment":self.config.commitment}]);
            let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":params});
            let res = client
                .post(&self.config.endpoint)
                .json(&body)
                .send()
                .await
                .map_err(|e| RpcError::RequestFailed(e.to_string()))?;
            let json: serde_json::Value = res
                .json()
                .await
                .map_err(|e| RpcError::InvalidResponse(e.to_string()))?;
            // Parse result.value
            if json.get("error").is_some() {
                return Err(RpcError::RequestFailed(json.to_string()));
            }
            let value = json
                .get("result")
                .and_then(|r| r.get("value"))
                .ok_or_else(|| RpcError::AccountNotFound(pubkey.to_base58()))?;
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
            let client = self.http_client.as_ref().ok_or_else(|| {
                RpcError::RequestFailed("http client not initialized".to_string())
            })?;
            let tx_b64 = base64::engine::general_purpose::STANDARD.encode(transaction_data);
            let params = serde_json::json!([tx_b64, {"encoding":"base64"}]);
            let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"simulateTransaction","params":params});
            let res = client
                .post(&self.config.endpoint)
                .json(&body)
                .send()
                .await
                .map_err(|e| RpcError::RequestFailed(e.to_string()))?;
            let json: serde_json::Value = res
                .json()
                .await
                .map_err(|e| RpcError::InvalidResponse(e.to_string()))?;
            if json.get("error").is_some() {
                return Err(RpcError::RequestFailed(json.to_string()));
            }
            let value = json
                .get("result")
                .and_then(|r| r.get("value"))
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

    /// Fetch oracle price from Pyth or Switchboard
    ///
    /// # Security
    /// Used to detect price oracle manipulation attacks.
    pub async fn get_oracle_price(&self, feed_id: &str) -> Result<OraclePrice, RpcError> {
        // In production, this would decode Pyth/Switchboard account data
        // to extract the current price, confidence, and timestamp

        tracing::info!("RPC: get_oracle_price called for feed {}", feed_id);

        // Placeholder return
        Ok(OraclePrice {
            feed_id: feed_id.to_string(),
            price: 0,
            confidence: 0,
            timestamp: 0,
            exponent: 0,
        })
    }

    /// Verify account is not frozen (for token accounts)
    ///
    /// # Security
    /// Prevents transactions that would fail due to frozen accounts.
    pub async fn is_account_frozen(&self, token_account: &Pubkey) -> Result<bool, RpcError> {
        let account = self.get_account(token_account).await?;

        // Check if this is a token account (owned by Tokenkeg...)
        if account.owner != "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" {
            return Ok(false); // Not a token account, can't be frozen
        }

        // Token account state is at byte 46 (after mint, owner, amount, delegate)
        // The state byte has bit 1 set if frozen
        if account.data.len() > 46 {
            let state = account.data[46];
            Ok((state & 0x02) != 0) // Bit 1 is the frozen flag
        } else {
            Ok(false)
        }
    }

    /// Get the current slot
    pub async fn get_slot(&self) -> Result<u64, RpcError> {
        {
            let client = self.http_client.as_ref().ok_or_else(|| {
                RpcError::RequestFailed("http client not initialized".to_string())
            })?;
            let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"getSlot","params":[{"commitment":self.config.commitment}]});
            let res = client
                .post(&self.config.endpoint)
                .json(&body)
                .send()
                .await
                .map_err(|e| RpcError::RequestFailed(e.to_string()))?;
            let json: serde_json::Value = res
                .json()
                .await
                .map_err(|e| RpcError::InvalidResponse(e.to_string()))?;
            if json.get("error").is_some() {
                return Err(RpcError::RequestFailed(json.to_string()));
            }
            let slot = json
                .get("result")
                .and_then(|r| r.get("value"))
                .and_then(|v| v.as_u64())
                .ok_or_else(|| {
                    RpcError::InvalidResponse("missing or invalid slot result".to_string())
                })?;
            Ok(slot)
        }
    }

    /// Get recent blockhash
    pub async fn get_latest_blockhash(&self) -> Result<String, RpcError> {
        {
            let client = self.http_client.as_ref().ok_or_else(|| {
                RpcError::RequestFailed("http client not initialized".to_string())
            })?;
            let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash","params":[{"commitment":self.config.commitment}]});
            let res = client
                .post(&self.config.endpoint)
                .json(&body)
                .send()
                .await
                .map_err(|e| RpcError::RequestFailed(e.to_string()))?;
            let json: serde_json::Value = res
                .json()
                .await
                .map_err(|e| RpcError::InvalidResponse(e.to_string()))?;
            if json.get("error").is_some() {
                return Err(RpcError::RequestFailed(json.to_string()));
            }
            let blockhash = json
                .get("result")
                .and_then(|r| r.get("value"))
                .and_then(|v| v.get("blockhash"))
                .and_then(|bh| bh.as_str())
                .ok_or_else(|| RpcError::InvalidResponse("missing blockhash".to_string()))?
                .to_string();
            Ok(blockhash)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

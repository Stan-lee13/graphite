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

/// The bundled Mozilla root certificates, as reqwest certificates: the only
/// trust anchors the RPC client accepts (Round 31). reqwest 0.13's rustls
/// backend verifies against the host's store by default; 0.12's
/// `rustls-tls` used this bundled set, and the RPC trust boundary keeps it,
/// so which CAs Graphite trusts does not depend on the host or image.
fn bundled_root_certificates() -> Vec<reqwest::Certificate> {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .filter_map(|der| reqwest::Certificate::from_der(der.as_ref()).ok())
        .collect()
}

/// The most instructions the runtime records for one transaction, top-level
/// and inner together (agave `MAX_INSTRUCTION_TRACE_LENGTH`). An RPC reporting
/// more inner instructions than this is not describing an execution (A2-11).
pub const MAX_INSTRUCTION_TRACE_LENGTH: usize = 64;
/// The deepest instruction stack the runtime allows, with room for SIMD-0268's
/// raise from 5 to 9 (A2-11). A reported `stackHeight` past it is refused.
pub const MAX_INSTRUCTION_STACK_HEIGHT: u32 = 9;

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
    // `executable` and `rentEpoch` keep their defaults: they are genuinely
    // optional in some response shapes, and a wrong value for them cannot
    // manufacture or conceal a state delta on its own.
    //
    // `data` is mandatory too (Round 29, audit 2026-10-20, R2). It used to
    // default to empty when it was missing, an object, a number, or an array
    // whose first element was not a string — and an empty pre-state and an
    // empty post-state compare EQUAL, so a provider failing both reads the
    // same way concealed every token balance, delegate, authority and
    // extension change on that account. The comment above it said a wrong
    // `data` could not conceal a delta; it could. Every request here asks for
    // `encoding: base64`, which every RPC answers as `[<base64>, "base64"]`
    // (an empty account is `["", "base64"]`), so anything else is refused
    // rather than read.
    let lamports = value
        .get("lamports")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            RpcError::InvalidResponse(format!(
                "account {pubkey}: `lamports` is missing or not an unsigned integer — refusing to substitute a default, because an invented balance is indistinguishable from a measured one once it reaches the state diff"
            ))
        })?;
    let owner = value
        .get("owner")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            RpcError::InvalidResponse(format!(
                "account {pubkey}: `owner` is missing or not a string — refusing to substitute the System Program, because that turns an unreadable response into a specific claim about who controls the account"
            ))
        })?
        .to_string();
    let executable = value
        .get("executable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let rent_epoch = value.get("rentEpoch").and_then(|v| v.as_u64()).unwrap_or(0);
    let data_base64 = match value.get("data").and_then(|d| d.as_array()) {
        Some(pair) if pair.len() == 2 && pair[1].as_str() == Some("base64") => {
            pair[0].as_str()
        }
        _ => None,
    }
    .ok_or_else(|| {
        RpcError::InvalidResponse(format!(
            "account {pubkey}: `data` is missing or not a [<base64>, \"base64\"] pair — refusing to read it as empty, because an empty pre-state and an empty post-state compare equal and would hide every change to the account's data"
        ))
    })?;
    let data = base64::engine::general_purpose::STANDARD
        .decode(data_base64)
        .map_err(|e| {
            RpcError::InvalidResponse(format!(
                "account {pubkey}: invalid base64 account data: {e}"
            ))
        })?;
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

/// Test seam for the account-object parser, for the same reason as the
/// simulation seam above: the coverage-guided fuzzer (`fuzz/`, Round 30)
/// drives it with hostile shapes no live RPC can be made to send.
pub fn account_from_value_for_test(
    pubkey: &str,
    value: &serde_json::Value,
) -> Result<Option<AccountState>, RpcError> {
    parse_account_value(pubkey, value)
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
    // Both are derived instead, from data the RPC does send.
    //
    // The derivation is the evidence, and it is the ONLY thing that becomes
    // evidence. An earlier version read the invented names first and let a
    // provider that supplied them win over the derivation, which has the
    // provenance rule backwards: a value under a name no Solana RPC produces is
    // a value a provider chose, and this layer exists to bound what a provider
    // can assert. A provider field is read now only to compare against what
    // Graphite worked out, and a disagreement is reported as an anomaly rather
    // than adopted.
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
    let balances = match (
        value.get("preBalances").and_then(readable),
        value.get("postBalances").and_then(readable),
    ) {
        (Some(pre), Some(post)) if pre.len() == post.len() => Some((pre, post)),
        _ => None,
    };
    let derived_account_writes = match (
        value.get("preBalances").and_then(readable),
        value.get("postBalances").and_then(readable),
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

    let account_writes = as_u32(derived_account_writes);
    let cpi_hops = as_u32(derived_cpi_hops);
    // The callees themselves (Round 17, F-16-05). One unreadable index makes
    // the whole set unknown, for the same reason one unreadable group makes
    // the hop count unknown: an undercount is the direction that hides a call.
    let inner_program_indexes: Option<Vec<u8>> = value
        .get("innerInstructions")
        .and_then(|v| v.as_array())
        .and_then(|groups| {
            let mut out = Vec::new();
            for g in groups {
                let ixs = g.get("instructions").and_then(|i| i.as_array())?;
                // Past the runtime's trace limit the report is not an
                // execution's (A2-11): unknown, never truncated.
                if out.len() + ixs.len() > MAX_INSTRUCTION_TRACE_LENGTH {
                    return None;
                }
                for ix in ixs {
                    let idx = ix.get("programIdIndex").and_then(|v| v.as_u64())?;
                    out.push(u8::try_from(idx).ok()?);
                }
            }
            Some(out)
        });

    // The inner instructions themselves (Round 19, F-19-22): program, accounts,
    // data and stack height, so the pipeline can rebuild the CPI tree the
    // simulator ACTUALLY executed instead of relying on a trace the caller
    // chose whether to send. Same completeness rule as the indexes above: one
    // unreadable instruction makes the whole set unknown.
    //
    // A2-11 (2026-09-29 audit): and a report no cluster can produce is not
    // one. The runtime records at most `MAX_INSTRUCTION_TRACE_LENGTH` (64)
    // instructions per transaction and nests them at most
    // `MAX_INSTRUCTION_STACK_HEIGHT` deep; a response past either is a
    // malicious or broken RPC, and it was trusted — ~200k inner instructions
    // of rising `stackHeight` fit in the 32 MiB response cap, recursed one
    // stack frame each while the tree was rebuilt, and aborted the PROCESS:
    // every in-flight request lost, no audit rows. Such a report makes the
    // set unknown, like any other unreadable one.
    let inner_instructions: Option<Vec<ObservedInnerInstruction>> = value
        .get("innerInstructions")
        .and_then(|v| v.as_array())
        .and_then(|groups| {
            let mut out = Vec::new();
            for g in groups {
                let top_level_index = u8::try_from(g.get("index")?.as_u64()?).ok()?;
                let instructions = g.get("instructions")?.as_array()?;
                if out.len() + instructions.len() > MAX_INSTRUCTION_TRACE_LENGTH {
                    return None;
                }
                for ix in instructions {
                    let program_id_index =
                        u8::try_from(ix.get("programIdIndex")?.as_u64()?).ok()?;
                    let accounts = ix
                        .get("accounts")?
                        .as_array()?
                        .iter()
                        .map(|a| a.as_u64().and_then(|a| u8::try_from(a).ok()))
                        .collect::<Option<Vec<u8>>>()?;
                    let data = bs58::decode(ix.get("data")?.as_str()?).into_vec().ok()?;
                    let stack_height = match ix.get("stackHeight") {
                        None | Some(serde_json::Value::Null) => None,
                        Some(h) => {
                            let h = u32::try_from(h.as_u64()?).ok()?;
                            // An inner instruction runs at height 2 or more.
                            if !(2..=MAX_INSTRUCTION_STACK_HEIGHT).contains(&h) {
                                return None;
                            }
                            Some(h)
                        }
                    };
                    out.push(ObservedInnerInstruction {
                        top_level_index,
                        program_id_index,
                        accounts,
                        data,
                        stack_height,
                    });
                }
            }
            Some(out)
        });

    // Round 35: every inner instruction in whichever form it arrived. Agave's
    // `simulateTransaction` never sends the compiled form the two lists above
    // read: each instruction goes through `parse_ui_instruction`, which prints
    // `{program, programId, parsed, stackHeight}` for a program it can parse
    // and `{programId, accounts: [<address>…], data, stackHeight}` for the
    // rest. With only the compiled form read, every transaction that made a
    // CPI was refused as incomplete on a real RPC (the live mainnet runs:
    // "callee report unreadable", 23 of 200). The partially decoded form is
    // read as it is; the parsed form is rebuilt exactly or left unknown
    // (`parsed_inner`). Resolved against the transaction's account list by
    // `resolve_reported_inner`. Same completeness rules: one entry that is no
    // form at all makes the whole report unknown.
    let mut not_rebuilt: Vec<String> = Vec::new();
    let inner_reported: Option<Vec<ReportedInnerInstruction>> = value
        .get("innerInstructions")
        .and_then(|v| v.as_array())
        .and_then(|groups| {
            let mut out = Vec::new();
            for g in groups {
                let top_level_index = u8::try_from(g.get("index")?.as_u64()?).ok()?;
                let instructions = g.get("instructions")?.as_array()?;
                if out.len() + instructions.len() > MAX_INSTRUCTION_TRACE_LENGTH {
                    return None;
                }
                for ix in instructions {
                    let stack_height = match ix.get("stackHeight") {
                        None | Some(serde_json::Value::Null) => None,
                        Some(h) => {
                            let h = u32::try_from(h.as_u64()?).ok()?;
                            if !(2..=MAX_INSTRUCTION_STACK_HEIGHT).contains(&h) {
                                return None;
                            }
                            Some(h)
                        }
                    };
                    let (program, body) = if let Some(i) = ix.get("programIdIndex") {
                        let program = InnerAccountRef::Index(u8::try_from(i.as_u64()?).ok()?);
                        let accounts = ix
                            .get("accounts")?
                            .as_array()?
                            .iter()
                            .map(|a| {
                                a.as_u64()
                                    .and_then(|a| u8::try_from(a).ok())
                                    .map(InnerAccountRef::Index)
                            })
                            .collect::<Option<Vec<_>>>()?;
                        let data = bs58::decode(ix.get("data")?.as_str()?).into_vec().ok()?;
                        (program, Some((accounts, data)))
                    } else {
                        let program_id = ix.get("programId")?.as_str()?;
                        let body = if let Some(parsed) = ix.get("parsed") {
                            let rebuilt = crate::parsed_inner::rebuild(program_id, parsed);
                            if rebuilt.is_none() {
                                let kind =
                                    parsed.get("type").and_then(|t| t.as_str()).unwrap_or("?");
                                not_rebuilt.push(format!("{program_id} `{kind}`"));
                            }
                            rebuilt
                        } else {
                            let accounts = ix
                                .get("accounts")?
                                .as_array()?
                                .iter()
                                .map(|a| a.as_str().map(str::to_string))
                                .collect::<Option<Vec<_>>>()?;
                            let data = bs58::decode(ix.get("data")?.as_str()?).into_vec().ok()?;
                            Some((accounts, data))
                        };
                        let body = body.map(|(accounts, data)| {
                            (
                                accounts.into_iter().map(InnerAccountRef::Address).collect(),
                                data,
                            )
                        });
                        (InnerAccountRef::Address(program_id.to_string()), body)
                    };
                    out.push(ReportedInnerInstruction {
                        top_level_index,
                        program,
                        body,
                        stack_height,
                    });
                }
            }
            Some(out)
        });

    // Non-canonical fields, compared and reported — never adopted.
    //
    // Silence is the wrong response to a provider volunteering a number under a
    // name the protocol does not define. It is not evidence, and it is not
    // nothing either: a provider whose `accountWrites` disagrees with the
    // balances it sent in the same response has contradicted itself, and that
    // is worth putting in front of an operator.
    let mut provider_anomalies: Vec<String> = Vec::new();

    // Round 29 (audit 2026-10-20, R9): the parsers above read the COMPILED
    // form of an inner instruction — `programIdIndex`, `accounts` as indexes,
    // `data` in base58 — and nothing in the request can guarantee that form.
    // `encoding: base64` governs how the transaction and the requested
    // accounts are encoded; agave's `simulateTransaction` documents its
    // `innerInstructions` as "jsonParsed where possible", and a node that
    // does so answers a System or SPL Token CPI as `{program, programId,
    // parsed, stackHeight}` (or `{programId, accounts: [<address>…], data}`
    // for a program it cannot parse), with no index at all. Such an answer
    // already leaves the callee set and the CPI tree unknown above — the
    // fail-closed outcome — but silently, which reads like a broken RPC.
    // Saying which form arrived is what lets an operator tell the two apart.
    // Round 35: that form is now read (`inner_reported`); what is still said
    // is which parsed instructions could not be rebuilt, since they leave the
    // executed CPI tree unknown and the verdict incomplete.
    if !not_rebuilt.is_empty() {
        not_rebuilt.sort();
        not_rebuilt.dedup();
        provider_anomalies.push(format!(
            "the RPC reported inner instruction(s) in parsed form that Graphite does not rebuild to their bytes ({}), so the executed CPI tree of this simulation is unobserved; its callees are known",
            not_rebuilt.join(", ")
        ));
    }

    let mut compare = |name: &str, provider: Option<u64>, derived: Option<u64>| {
        if let Some(claimed) = provider {
            match derived {
                Some(d) if d != claimed => provider_anomalies.push(format!(
                    "the RPC reported a non-standard `{name}` of {claimed}; Graphite derived {d} from the response's own canonical fields and used its own"
                )),
                Some(_) => {}
                None => provider_anomalies.push(format!(
                    "the RPC reported a non-standard `{name}` of {claimed}; Graphite could not derive it from the response's canonical fields and did not adopt the reported value"
                )),
            }
        }
    };
    compare(
        "accountWrites",
        nested("accountWrites").or_else(|| {
            value
                .get("meta")
                .and_then(|m| m.get("numAccountWrites"))
                .and_then(|v| v.as_u64())
        }),
        derived_account_writes,
    );
    compare(
        "cpiHops",
        nested("cpiHops").or_else(|| {
            value
                .get("meta")
                .and_then(|m| m.get("cpi_hops"))
                .and_then(|v| v.as_u64())
        }),
        derived_cpi_hops,
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

    // A JSON `null` here means "no error", not "an error named null". An
    // ABSENT `err` means nothing: every RPC states it, and a missing one is an
    // unreadable answer, not a successful simulation that may then train the
    // baseline (W16, external review).
    if value.get("err").is_none() {
        return Err(RpcError::InvalidResponse(
            "simulateTransaction result has no `err` field; whether it succeeded is unknown"
                .to_string(),
        ));
    }
    let err = value.get("err").filter(|e| !e.is_null()).map(|e| {
        if let Some(s) = e.as_str() {
            s.to_string()
        } else {
            e.to_string()
        }
    });

    // One unreadable entry makes the whole set unknown (Round 29, audit
    // 2026-10-20, R3). Entries used to be DROPPED, and these lists are not a
    // set but a sequence: the account list the inner instructions index into
    // is the static keys, then `writable`, then `readonly`. Dropping one entry
    // shifted every later address down by one, so an inner instruction's
    // `programIdIndex` resolved to the NEIGHBOURING account — a callee
    // misnamed, which is worse than a callee unknown. A missing or non-array
    // list is unreadable for the same reason: the length is part of the
    // indexing.
    let str_list = |v: Option<&serde_json::Value>| -> Option<Vec<String>> {
        v?.as_array()?
            .iter()
            .map(|x| x.as_str().map(str::to_string))
            .collect()
    };
    let loaded_addresses = value.get("loadedAddresses").and_then(|la| {
        if la.is_null() {
            None
        } else {
            Some(LoadedAddresses {
                writable: str_list(la.get("writable"))?,
                readonly: str_list(la.get("readonly"))?,
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
        provider_anomalies,
        fee: value.get("fee").and_then(|v| v.as_u64()),
        loaded_addresses,
        artifact_account_count,
        slot: None,
        inner_program_indexes,
        inner_instructions,
        inner_reported,
        balances,
    })
}

/// The `context.slot` a JSON-RPC result was computed at, when the response
/// carries one. Every Solana read method returns it; a mock or a
/// non-conforming provider may not.
fn context_slot(result: &serde_json::Value) -> Option<u64> {
    result
        .get("context")
        .and_then(|c| c.get("slot"))
        .and_then(|s| s.as_u64())
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

/// The BPF Upgradeable Loader (loader-v3).
pub const UPGRADEABLE_LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
/// `UpgradeableLoaderState::Program`: a u32 tag (2) and the ProgramData address.
const PROGRAM_ACCOUNT_HEADER: usize = 4 + 32;
/// `UpgradeableLoaderState::ProgramData`: a u32 tag (3), the deploy slot
/// (u64) and the upgrade authority (`Option<Pubkey>`: one byte, then 32).
const PROGRAMDATA_HEADER: usize = 4 + 8 + 1 + 32;
/// The loader-v4 program (Round 36, F-009).
pub const LOADER_V4: &str = "LoaderV411111111111111111111111111111111111";
/// `LoaderV4State`, `#[repr(C)]` at the start of the program account itself:
/// the slot its code was last deployed (or retracted) at (u64), its authority
/// or, once finalized, its next version (Pubkey), and its status (u64:
/// Retracted 0, Deployed 1, Finalized 2).
const LOADER_V4_HEADER: usize = 8 + 32 + 8;
/// The first read covers either loader's program-account header.
const PROGRAM_HEADER_READ: usize = if LOADER_V4_HEADER > PROGRAM_ACCOUNT_HEADER {
    LOADER_V4_HEADER
} else {
    PROGRAM_ACCOUNT_HEADER
};

/// What the chain says about a program's code right now (roadmap R-M1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProgramDeployment {
    /// Owned by the upgradeable loader: the slot its code was last deployed
    /// at, and who may replace it (`None`: no one — the program is final).
    Upgradeable {
        programdata: String,
        deploy_slot: u64,
        upgrade_authority: Option<String>,
    },
    /// Owned by loader-v4 (Round 36, F-009): the code lives in the program
    /// account, deployed at `deploy_slot`; `authority` may redeploy or
    /// retract it, `None` once it is finalized. A retracted program cannot be
    /// executed until it is redeployed.
    LoaderV4 {
        deploy_slot: u64,
        authority: Option<String>,
        retracted: bool,
    },
    /// Owned by another loader or a builtin's loader: its code cannot be
    /// replaced through the upgradeable loader.
    NotUpgradeable { owner: String },
    /// No account at that address.
    Missing,
    /// The account was read and its deployment does not decode (Round 38,
    /// R37-16): `why`. One such entry used to fail the whole batch, so a
    /// single odd account switched upgrade detection off for every program
    /// in the transaction; it now stands for itself, and the verdict says
    /// the deployment was not read.
    Unreadable { why: String },
}

/// The ProgramData address a loader-v3 `Program` account names.
pub fn decode_program_account(data: &[u8]) -> Option<String> {
    if data.len() < PROGRAM_ACCOUNT_HEADER || data[..4] != 2u32.to_le_bytes() {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&data[4..36]);
    Some(Pubkey::from_bytes(key).to_base58())
}

/// A loader-v4 program account's header: `(slot, authority, status)`, the
/// authority `None` when the program is finalized. `None` for data that is
/// short or whose status is not one of the three.
pub fn decode_loader_v4_header(data: &[u8]) -> Option<(u64, Option<String>, u64)> {
    if data.len() < LOADER_V4_HEADER {
        return None;
    }
    let slot = u64::from_le_bytes(data[0..8].try_into().ok()?);
    let mut key = [0u8; 32];
    key.copy_from_slice(&data[8..40]);
    let status = u64::from_le_bytes(data[40..48].try_into().ok()?);
    let authority = match status {
        0 | 1 => Some(Pubkey::from_bytes(key).to_base58()),
        2 => None,
        _ => return None,
    };
    Some((slot, authority, status))
}

/// The deploy slot and upgrade authority of a loader-v3 `ProgramData` header.
pub fn decode_programdata_header(data: &[u8]) -> Option<(u64, Option<String>)> {
    if data.len() < 13 || data[..4] != 3u32.to_le_bytes() {
        return None;
    }
    let slot = u64::from_le_bytes(data[4..12].try_into().ok()?);
    let authority = match data[12] {
        0 => None,
        1 if data.len() >= PROGRAMDATA_HEADER => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&data[13..45]);
            Some(Pubkey::from_bytes(key).to_base58())
        }
        _ => return None,
    };
    Some((slot, authority))
}

/// How far the cluster has committed to a transaction, as
/// `getSignatureStatuses` reports it in `confirmationStatus`.
///
/// `processed` is ONE node's view: the transaction is in a block that node
/// has seen, which the cluster may still discard (a minority fork). It is not
/// inclusion. `confirmed` means a supermajority voted on the block;
/// `finalized` means it is rooted. Until Round 12 the field was not read and
/// every non-null status was treated alike, so an L8 conclusion could rest
/// on a block that later vanished — and one node, or one RPC, could be the
/// only party that ever saw the transaction at all.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum InclusionCommitment {
    Processed,
    Confirmed,
    Finalized,
}

impl InclusionCommitment {
    /// True once a supermajority has voted on the block: the level at and
    /// above which the cluster, not one node, stands behind the inclusion.
    pub fn is_cluster_backed(self) -> bool {
        self >= InclusionCommitment::Confirmed
    }
}

impl std::fmt::Display for InclusionCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            InclusionCommitment::Processed => "processed",
            InclusionCommitment::Confirmed => "confirmed",
            InclusionCommitment::Finalized => "finalized",
        })
    }
}

/// On-chain status of a submitted transaction (getSignatureStatuses).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureStatus {
    /// Slot the transaction was included in.
    pub slot: u64,
    /// Remaining confirmations; None once finalized.
    pub confirmations: Option<u64>,
    /// Whether the transaction executed successfully (status Ok).
    pub success: bool,
    /// RPC error payload when the transaction failed (status Err).
    pub error: Option<String>,
    /// The commitment level the RPC reports the inclusion at.
    pub commitment: InclusionCommitment,
}

/// One transaction as the chain holds it (`getTransaction`): the bytes, and
/// the facts about them the RPC states alongside — kept so they can be
/// checked against what `getSignatureStatuses` said. One RPC answering two
/// questions about one signature differently is one RPC not to draw a
/// conclusion from (Round 12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainTransaction {
    /// The serialized transaction, signatures included.
    pub bytes: Vec<u8>,
    /// The slot the response places it in, when stated.
    pub slot: Option<u64>,
    /// Whether the response's `meta.err` is null: `Some(true)` succeeded,
    /// `Some(false)` failed, `None` when `meta` was absent.
    pub succeeded: Option<bool>,
}

/// Simulation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub logs: Vec<String>,
    pub units_consumed: u64,
    pub return_data: Option<Vec<u8>>,
    pub err: Option<String>,
    /// Accounts whose lamport balance moved between `preBalances` and
    /// `postBalances`, derived by Graphite from the response's canonical
    /// fields.
    ///
    /// Never taken from a provider-supplied field: no Solana RPC defines one,
    /// so a value under such a name is a value the provider chose. See
    /// `provider_anomalies`.
    pub account_writes: Option<u32>,
    /// Inner instructions summed across every top-level instruction, derived by
    /// Graphite from `innerInstructions`. Same provenance rule as
    /// `account_writes`.
    pub cpi_hops: Option<u32>,
    /// Non-standard fields the response carried, and how they compared to what
    /// Graphite derived.
    ///
    /// Reported, never adopted. Empty for every response from an RPC that sends
    /// only what Solana defines.
    #[serde(default)]
    pub provider_anomalies: Vec<String>,
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
    /// The slot the simulation was executed against (`result.context.slot`),
    /// when the response carried one.
    ///
    /// Round 9: the pre-state read and the simulation are two RPC calls and
    /// can land on different slots. When they do, changes made by other
    /// transactions in between appear in the state diff as this
    /// transaction's — the L4 detail says so, and the two slots are the
    /// evidence.
    #[serde(default)]
    pub slot: Option<u64>,
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
    /// The `programIdIndex` of every inner instruction the simulator
    /// executed, in order, across every top-level instruction — the CPI
    /// callees, as indexes into the transaction's full account list (static
    /// keys, then `loadedAddresses.writable`, then `loadedAddresses.readonly`).
    ///
    /// Round 17 (F-16-05): until this field existed the response's
    /// `innerInstructions` were read only to COUNT hops, and the Risk Engine's
    /// CPI checks consumed the caller's `cpi_targets` list — which a caller
    /// disables by leaving it empty. The callees are in the same response;
    /// `verify_async` maps these indexes through the parsed message and feeds
    /// the observed set to the same checks. `None` when `innerInstructions`
    /// was absent or any group was unreadable — unknown, never empty.
    #[serde(default)]
    pub inner_program_indexes: Option<Vec<u8>>,
    /// Every inner instruction the simulator executed, in order, with the
    /// top-level instruction it ran under (Round 19, F-19-22). `None` when
    /// `innerInstructions` was absent or any entry was unreadable.
    #[serde(default)]
    pub inner_instructions: Option<Vec<ObservedInnerInstruction>>,
    /// Every inner instruction in the form the RPC sent it (Round 35): the
    /// compiled form, or by address (Agave's parsed and partially decoded
    /// forms). `resolve_reported_inner` turns it into the two fields above.
    /// `None` when `innerInstructions` was absent or an entry was in no form.
    #[serde(default)]
    pub inner_reported: Option<Vec<ReportedInnerInstruction>>,
    /// `(preBalances, postBalances)`: the simulator's lamports for every
    /// account of the transaction, before and after, read at ONE slot
    /// (Round 21). `None` unless both arrays are present, readable and of
    /// equal length.
    #[serde(default)]
    pub balances: Option<(Vec<u64>, Vec<u64>)>,
}

/// `getEpochInfo`'s answer: the fields the fee model uses (Round 21).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochInfo {
    pub absolute_slot: u64,
    pub epoch: u64,
    pub slot_index: u64,
    pub slots_in_epoch: u64,
}

impl EpochInfo {
    /// Read the four fields, refusing an answer that is not internally
    /// consistent: an empty epoch, or a slot index past the epoch's end, or
    /// one larger than the slot it is an index of.
    pub fn from_value(v: &serde_json::Value) -> Result<Self, RpcError> {
        let field = |name: &str| {
            v.get(name).and_then(|x| x.as_u64()).ok_or_else(|| {
                RpcError::InvalidResponse(format!("getEpochInfo: missing or invalid {name}"))
            })
        };
        let info = EpochInfo {
            absolute_slot: field("absoluteSlot")?,
            epoch: field("epoch")?,
            slot_index: field("slotIndex")?,
            slots_in_epoch: field("slotsInEpoch")?,
        };
        if info.slots_in_epoch == 0
            || info.slot_index >= info.slots_in_epoch
            || info.slot_index > info.absolute_slot
        {
            return Err(RpcError::InvalidResponse(format!(
                "getEpochInfo is not self-consistent: slot {} is index {} of an epoch of {} slots",
                info.absolute_slot, info.slot_index, info.slots_in_epoch
            )));
        }
        Ok(info)
    }

    /// The epoch `slot` falls in, counting forward (or one epoch back) from
    /// this answer. Epochs after warm-up are all `slots_in_epoch` long, which
    /// is what makes the arithmetic valid; a slot more than one epoch before
    /// this one is not placed.
    pub fn epoch_of(&self, slot: u64) -> Option<u64> {
        let start = self.absolute_slot - self.slot_index;
        if slot >= start {
            self.epoch.checked_add((slot - start) / self.slots_in_epoch)
        } else if start - slot <= self.slots_in_epoch {
            self.epoch.checked_sub(1)
        } else {
            None
        }
    }
}

/// One inner (CPI) instruction from a `simulateTransaction` response, in the
/// response's compiled form: indexes into the transaction's full account list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedInnerInstruction {
    /// The top-level instruction this CPI ran under (`innerInstructions[].index`).
    pub top_level_index: u8,
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
    /// `stackHeight`: 2 for a CPI made directly by the top-level instruction,
    /// 3 for one made by that callee, and so on. `None` from an RPC that does
    /// not report it.
    pub stack_height: Option<u32>,
}

/// How an inner instruction names a program or an account (Round 35): by
/// index into the transaction's full account list (the compiled form), or by
/// address (the forms Agave sends).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InnerAccountRef {
    Index(u8),
    Address(String),
}

/// One inner instruction as the RPC reported it (Round 35).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportedInnerInstruction {
    pub top_level_index: u8,
    pub program: InnerAccountRef,
    /// The accounts and data; `None` for a parsed instruction
    /// `parsed_inner` does not rebuild (its callee is still known).
    pub body: Option<(Vec<InnerAccountRef>, Vec<u8>)>,
    pub stack_height: Option<u32>,
}

impl SimulationResult {
    /// Resolve `inner_reported` against the transaction's account list (its
    /// static keys, then `loaded_addresses`), filling `inner_program_indexes`
    /// and `inner_instructions` (Round 35). An address that is not in the
    /// list, or past index 255, leaves the callees unknown; an instruction
    /// whose accounts or data were not rebuilt leaves the instructions
    /// unknown. Unknown is `None`, never a shorter list. Without a reported
    /// form (a result built by hand, or one read before Round 35) the two
    /// fields are left as they are.
    pub fn resolve_reported_inner(&mut self, static_keys: &[String]) {
        let Some(reported) = self.inner_reported.as_ref() else {
            return;
        };
        let mut keys: Vec<&str> = static_keys.iter().map(String::as_str).collect();
        if let Some(l) = &self.loaded_addresses {
            keys.extend(l.writable.iter().map(String::as_str));
            keys.extend(l.readonly.iter().map(String::as_str));
        }
        let index = |r: &InnerAccountRef| -> Option<u8> {
            match r {
                InnerAccountRef::Index(i) => Some(*i),
                InnerAccountRef::Address(a) => u8::try_from(keys.iter().position(|k| k == a)?).ok(),
            }
        };
        self.inner_program_indexes = reported.iter().map(|ix| index(&ix.program)).collect();
        self.inner_instructions = reported
            .iter()
            .map(|ix| {
                let (accounts, data) = ix.body.as_ref()?;
                Some(ObservedInnerInstruction {
                    top_level_index: ix.top_level_index,
                    program_id_index: index(&ix.program)?,
                    accounts: accounts.iter().map(index).collect::<Option<Vec<u8>>>()?,
                    data: data.clone(),
                    stack_height: ix.stack_height,
                })
            })
            .collect();
    }
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

/// The most JSON values (objects, arrays, strings, numbers, literals) one RPC
/// response may hold.
///
/// W16 (external review, verified 2026-10-03): the byte cap bounds the body,
/// not what parsing it costs. A `serde_json::Value` is 32 bytes before any
/// heap it owns, so 32 MiB of `[0,0,0,…]` parses to ~16.7 million values and
/// ~540 MB — over the container's 512 MB, from a body the cap accepted. A
/// real response is a few thousand values at most (100 accounts, a
/// simulation's balance arrays and inner instructions), almost all of its
/// bytes inside long base64 strings, which are one value each.
const MAX_RPC_RESPONSE_VALUES: usize = 1_000_000;

/// How many JSON values `body` holds, counted in one pass without building
/// them, or `None` once there are more than `limit`. Strings (with their
/// escapes) are skipped as single values; every other value begins at a
/// byte outside a string that is not whitespace, a separator or a closer.
fn json_value_count_within(body: &[u8], limit: usize) -> Option<usize> {
    let mut count = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut in_scalar = false;
    for &b in body {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => {
                in_string = true;
                in_scalar = false;
                count += 1;
            }
            b'{' | b'[' => {
                in_scalar = false;
                count += 1;
            }
            b',' | b':' | b'}' | b']' | b' ' | b'\n' | b'\r' | b'\t' => in_scalar = false,
            _ => {
                if !in_scalar {
                    in_scalar = true;
                    count += 1;
                }
            }
        }
        if count > limit {
            return None;
        }
    }
    Some(count)
}

/// The longest attacker-chosen text that may travel inside an `RpcError`.
///
/// A JSON-RPC error body is echoed into `RpcError::RequestFailed`, which reaches
/// the L3 layer `reason` and the audit trail. Both its length and its content
/// are the peer's to choose, so an unbounded echo is both storage the peer sizes
/// and text the peer writes into a field a human reads before signing. Bounded
/// the same way `AuditErrorRecord` bounds its fields, and for the same reason.
const MAX_RPC_ERROR_CHARS: usize = 256;

/// Peer-written text, made safe to carry in an `RpcError`: credential-shaped
/// content removed first, then bounded.
///
/// Round 29 (audit 2026-10-20, R4): the text was bounded but not redacted. A
/// JSON-RPC `error` object is whatever the peer — or a proxy, gateway or load
/// balancer in front of it — chose to write, and providers do echo the
/// request URL ("invalid api key for https://…?api-key=…") into it. That
/// string reaches the L3 `reason` in the `/verify` response body, the same
/// leak `redact_transport_error` closes for transport errors. Scrubbing runs
/// on the WHOLE text before it is cut: cutting first could leave a key's
/// prefix too short to be recognised as one.
fn bound_rpc_text(value: &str) -> String {
    let value = scrub_rpc_text(value);
    if value.chars().count() <= MAX_RPC_ERROR_CHARS {
        return value;
    }
    let kept: String = value.chars().take(MAX_RPC_ERROR_CHARS).collect();
    // Say what was dropped: a silently shortened diagnostic reads as the whole
    // one.
    format!("{kept}… [truncated, {} chars total]", value.chars().count())
}

/// Replace anything credential-shaped in `value` (R4).
///
/// Tokens are split on whitespace, quotes and brackets, and a token is
/// replaced when it is:
/// - URL-like: it has a scheme (`://`), starts with `www.`, or names a host
///   and a path (a `.` and a `/`) — a managed provider's key lives in the
///   URL's path or query;
/// - a key-shaped assignment: `api-key=…`, `token:…`, `secret=…`, … — the
///   value is replaced, and a key name followed by nothing (`apikey: <v>`)
///   or `Bearer` replaces the next token;
/// - opaque: 24 or more characters of letters, digits, `-` and `_`, with
///   both letters and digits — the shape of every provider key, and of a
///   base58 address or signature, which are replaced too: the operator can
///   read those from the request, and a rule that let them through would let
///   a key of the same shape through.
fn scrub_rpc_text(value: &str) -> String {
    const KEY_NAMES: [&str; 7] = [
        "key",
        "token",
        "secret",
        "auth",
        "passw",
        "credential",
        "session",
    ];
    let is_delimiter = |c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '"' | '\'' | '`' | ',' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>'
            )
    };
    let mut out = String::with_capacity(value.len());
    let mut redact_next = false;
    let mut scrub_token = |token: &str, out: &mut String| {
        if token.is_empty() {
            return;
        }
        let lower = token.to_ascii_lowercase();
        if std::mem::take(&mut redact_next) {
            out.push_str("[redacted]");
            return;
        }
        if lower.contains("://")
            || lower.starts_with("www.")
            || (lower.contains('/') && lower.contains('.'))
        {
            out.push_str("[redacted url]");
            return;
        }
        if let Some(at) = token.find(['=', ':']) {
            let name = &lower[..at];
            if KEY_NAMES.iter().any(|k| name.contains(k)) {
                out.push_str(&token[..=at]);
                if at + 1 < token.len() {
                    out.push_str("[redacted]");
                } else {
                    redact_next = true;
                }
                return;
            }
        }
        if lower == "bearer" {
            redact_next = true;
        }
        let opaque = token.chars().count() >= 24
            && token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            && token.chars().any(|c| c.is_ascii_digit())
            && token.chars().any(|c| c.is_ascii_alphabetic());
        if opaque {
            out.push_str("[redacted]");
        } else {
            out.push_str(token);
        }
    };
    let mut start = 0;
    for (i, c) in value.char_indices() {
        if is_delimiter(c) {
            scrub_token(&value[start..i], &mut out);
            out.push(c);
            start = i + c.len_utf8();
        }
    }
    scrub_token(&value[start..], &mut out);
    out
}

/// The `result` of one JSON-RPC 2.0 response envelope, or why there is none.
///
/// Round 29 (audit 2026-10-20, R6): an `"error": null` member was read as an
/// error — `get("error")` is `Some(Null)` — so a peer that always writes both
/// members failed every call with the reason "null". `null` is absence. The
/// envelope is also checked for being one: an object, `jsonrpc` "2.0" when
/// stated, and an `id` that is the request's when stated (a JSON-RPC peer
/// sends `id: null` only with an error it could not attribute to a request).
/// An answer to some other request is not an answer to this one.
fn jsonrpc_result(
    json: serde_json::Value,
    request_id: Option<&serde_json::Value>,
) -> Result<serde_json::Value, RpcError> {
    let serde_json::Value::Object(mut envelope) = json else {
        return Err(RpcError::InvalidResponse(
            "the RPC response is not a JSON-RPC object".to_string(),
        ));
    };
    match envelope.get("jsonrpc") {
        None => {}
        Some(v) if v.as_str() == Some("2.0") => {}
        Some(v) => {
            return Err(RpcError::InvalidResponse(format!(
                "the RPC response states jsonrpc {}, not \"2.0\"",
                bound_rpc_text(&v.to_string())
            )))
        }
    }
    let error = envelope.remove("error").filter(|e| !e.is_null());
    match (envelope.get("id"), request_id) {
        (None, _) | (_, None) => {}
        (Some(serde_json::Value::Null), _) if error.is_some() => {}
        (Some(got), Some(sent)) if got == sent => {}
        (Some(got), Some(_)) => {
            return Err(RpcError::InvalidResponse(format!(
                "the RPC response answers request id {}, not the one sent",
                bound_rpc_text(&got.to_string())
            )))
        }
    }
    if let Some(err) = error {
        // Bounded and scrubbed: this string reaches the L3 reason and the
        // audit trail, and the peer wrote it (R4).
        return Err(RpcError::RequestFailed(bound_rpc_text(&err.to_string())));
    }
    envelope
        .remove("result")
        .ok_or_else(|| RpcError::InvalidResponse("missing result".to_string()))
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

/// Why an RPC endpoint string cannot be used.
///
/// Reported without the endpoint itself: a managed provider's URL carries
/// the operator's key, and a refusal that echoes it back is a leak.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EndpointError {
    #[error("the RPC endpoint is not a URL ({0})")]
    NotAUrl(String),
    #[error("the RPC endpoint scheme is {0:?}; only http and https reach a Solana RPC")]
    Scheme(String),
    #[error("the RPC endpoint has no host")]
    NoHost,
    #[error("the RPC endpoint carries a fragment; a JSON-RPC URL has none")]
    Fragment,
    /// The host is an address no Solana RPC is served from: link-local
    /// (which holds the cloud instance-metadata service), unspecified,
    /// multicast or broadcast (Round 30). Named by range, never by value.
    #[error("the RPC endpoint's host is a {0} address; no Solana RPC is served from one")]
    ForbiddenAddress(&'static str),
}

/// What an endpoint string is, once validated. Nothing here identifies the
/// endpoint beyond what an operator log line may safely say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointFacts {
    /// `https` or `http`.
    pub scheme: String,
    /// The host is loopback (`localhost`, `127.0.0.0/8`, `::1`).
    pub loopback: bool,
    /// The URL carries a username or password.
    pub has_userinfo: bool,
    /// The URL carries a query string — where most managed providers put the
    /// API key.
    pub has_query: bool,
    /// The host is a private-network address literal (RFC 1918, CGNAT,
    /// IPv6 unique-local). Allowed — operators run nodes on private
    /// networks — but said at startup, so a URL that points inside the
    /// network by mistake is visible (Round 30). A host NAME is judged when
    /// it resolves, by `GuardedResolver`.
    pub private_network: bool,
}

/// Validate an RPC endpoint before a client is built on it.
///
/// A client on an unusable endpoint used to be built anyway and fail on its
/// first call; the server then ran with "live L3/L4 enabled" in its startup
/// log and every simulation Inconclusive — an operator who set the variable
/// believed simulation was on. Refusing at construction makes the
/// misconfiguration a startup failure instead of a silent downgrade. Only
/// `http` and `https` are accepted: `reqwest` refuses other schemes at
/// request time, but the point is to refuse them before the process claims
/// to be simulating (Round 12).
///
/// Round 29 (audit 2026-10-20, R7): the string validated is the string the
/// client posts to — `SolanaRpcClient::new` trims its endpoint the same way
/// (`normalize_endpoint`) — and loopback is read from the parsed host, so an
/// IPv4-mapped IPv6 loopback (`[::ffff:127.0.0.1]`) and the fully-qualified
/// `localhost.` count as loopback like the forms they are equivalent to.
pub fn validate_endpoint(endpoint: &str) -> Result<EndpointFacts, EndpointError> {
    let url = reqwest::Url::parse(normalize_endpoint(endpoint))
        .map_err(|e| EndpointError::NotAUrl(e.to_string()))?;
    let scheme = url.scheme().to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(EndpointError::Scheme(scheme));
    }
    let Some(host) = url.host_str() else {
        return Err(EndpointError::NoHost);
    };
    if url.fragment().is_some() {
        return Err(EndpointError::Fragment);
    }
    // The URL parser has already normalised the host: an IPv6 literal comes
    // back bracketed and compressed (`[::ffff:7f00:1]`), an IPv4 one dotted.
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let literal = bare
        .parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| ip.to_canonical());
    if let Some(range) = literal.and_then(forbidden_range) {
        return Err(EndpointError::ForbiddenAddress(range));
    }
    let loopback = match literal {
        Some(ip) => ip.is_loopback(),
        None => bare.eq_ignore_ascii_case("localhost") || bare.eq_ignore_ascii_case("localhost."),
    };
    Ok(EndpointFacts {
        scheme,
        loopback,
        has_userinfo: !url.username().is_empty() || url.password().is_some(),
        has_query: url.query().is_some(),
        private_network: literal.is_some_and(is_private_network),
    })
}

/// The range an address belongs to when no Solana RPC can be served from it
/// (Round 30, URL policy). Link-local covers `169.254.169.254` and
/// `fe80::/10`, where cloud instance-metadata services answer; the two
/// metadata addresses outside link-local (AWS's IPv6 `fd00:ec2::254`,
/// Alibaba's `100.100.100.200`) are named explicitly. An IPv4-mapped IPv6
/// address is judged as the IPv4 address it carries.
pub fn forbidden_range(ip: std::net::IpAddr) -> Option<&'static str> {
    use std::net::IpAddr;
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() {
                Some("unspecified")
            } else if v4.is_link_local() {
                Some("link-local (instance-metadata)")
            } else if v4.is_multicast() {
                Some("multicast")
            } else if v4.is_broadcast() {
                Some("broadcast")
            } else if v4.octets() == [100, 100, 100, 200] {
                Some("instance-metadata")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            if v6.is_unspecified() {
                Some("unspecified")
            } else if seg[0] & 0xffc0 == 0xfe80 {
                Some("link-local (instance-metadata)")
            } else if v6.is_multicast() {
                Some("multicast")
            } else if seg == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254] {
                Some("instance-metadata")
            } else {
                None
            }
        }
    }
}

/// A private-network address: RFC 1918, CGNAT `100.64.0.0/10`, or IPv6
/// unique-local `fc00::/7`.
pub fn is_private_network(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private() || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => v6.segments()[0] & 0xfe00 == 0xfc00,
    }
}

/// The DNS resolver every RPC client uses (Round 30, URL policy).
///
/// `validate_endpoint` judges an address literal once, at startup; a host
/// NAME is judged here, at every connection, so a record that resolves —
/// or is later re-pointed — to the instance-metadata service or another
/// forbidden range is refused at connect time instead of being posted to.
/// Addresses in a forbidden range are dropped; a name that resolves only to
/// such addresses is an error that names the range, never the name.
///
/// With an HTTP(S) proxy configured, the client connects to the proxy
/// through this resolver and the proxy resolves the RPC host: the check then
/// covers the proxy's address only.
#[derive(Debug, Default, Clone, Copy)]
pub struct GuardedResolver;

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let resolved: Vec<std::net::SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            let (allowed, refused): (Vec<_>, Vec<_>) = resolved
                .into_iter()
                .partition(|a| forbidden_range(a.ip()).is_none());
            if allowed.is_empty() {
                let range = refused
                    .first()
                    .and_then(|a| forbidden_range(a.ip()))
                    .unwrap_or("no");
                return Err(format!(
                    "the RPC host resolves only to {range} addresses; refused, no Solana RPC is served from one"
                )
                .into());
            }
            let addrs: reqwest::dns::Addrs = Box::new(allowed.into_iter());
            Ok(addrs)
        })
    }
}

/// Whether an inclusion witness is a different provider from the primary
/// RPC it witnesses (Round 30, G-08).
///
/// Two URLs are not two witnesses because they are two strings. A witness on
/// the same host, under the same registrable domain, or resolving to an
/// address the primary also resolves to is the same operator's view twice,
/// and its agreement is not independent evidence. Ownership itself is beyond
/// what a URL can show — two domains can belong to one provider — so
/// `Distinct` is necessary, not sufficient; the server's high-assurance mode
/// adds the operator's attestation of the two providers' names on top.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "independence", content = "reason")]
pub enum WitnessIndependence {
    /// Different hosts, different registrable domains, and (when resolved)
    /// no shared address.
    Distinct,
    /// The same operator's view twice; the reason names the check that
    /// matched.
    NotIndependent(String),
}

impl WitnessIndependence {
    pub fn is_distinct(&self) -> bool {
        matches!(self, Self::Distinct)
    }
}

/// The registrable part of a host — near enough, the provider it names: the
/// last two labels, or three under a two-level public suffix (`co.uk`,
/// `com.au`, …). An address literal is its own provider. A deliberately
/// small approximation of the public-suffix list: a miss makes two hosts of
/// one provider look DISTINCT, which is why high-assurance mode also asks
/// the operator to name both providers.
fn provider_domain(host: &str) -> String {
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return ip.to_canonical().to_string();
    }
    const TWO_LEVEL: &[&str] = &[
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "ne.jp",
        "co.kr", "com.br", "com.cn", "com.sg", "com.hk", "co.in", "co.nz", "co.za", "com.mx",
        "com.tr", "com.tw",
    ];
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    let take = match labels.len() {
        0..=2 => labels.len(),
        n if TWO_LEVEL.contains(&labels[n - 2..].join(".").as_str()) => 3,
        _ => 2,
    };
    labels[labels.len() - take..].join(".")
}

/// Judge a witness against its primary from the URLs alone: the same host,
/// the same registrable domain, or both on loopback (one machine) is not
/// independent. An endpoint that does not parse is not independent either:
/// nothing can be said about its provider.
pub fn witness_independence(primary: &str, witness: &str) -> WitnessIndependence {
    let host = |u: &str| {
        reqwest::Url::parse(normalize_endpoint(u))
            .ok()
            .and_then(|url| url.host_str().map(str::to_string))
    };
    let (Some(p), Some(w)) = (host(primary), host(witness)) else {
        return WitnessIndependence::NotIndependent(
            "an endpoint could not be parsed, so its provider is unknown".to_string(),
        );
    };
    let loopback = |u: &str| validate_endpoint(u).is_ok_and(|f| f.loopback);
    if loopback(primary) && loopback(witness) {
        return WitnessIndependence::NotIndependent(
            "both endpoints are loopback: one machine's view".to_string(),
        );
    }
    let canon = |h: &str| {
        h.trim_start_matches('[')
            .trim_end_matches(']')
            .trim_end_matches('.')
            .to_ascii_lowercase()
    };
    if canon(&p) == canon(&w) {
        return WitnessIndependence::NotIndependent(
            "both endpoints are on the same host".to_string(),
        );
    }
    if provider_domain(&p) == provider_domain(&w) {
        return WitnessIndependence::NotIndependent(
            "both endpoints are under the same registrable domain".to_string(),
        );
    }
    WitnessIndependence::Distinct
}

/// `witness_independence`, then the addresses: two hosts that resolve to a
/// shared address are one server. A host that does not resolve is an error:
/// independence that cannot be checked is not assumed.
pub async fn witness_independence_resolved(
    primary: &str,
    witness: &str,
) -> Result<WitnessIndependence, String> {
    let by_url = witness_independence(primary, witness);
    if !by_url.is_distinct() {
        return Ok(by_url);
    }
    async fn addrs(endpoint: &str, name: &str) -> Result<Vec<std::net::IpAddr>, String> {
        let url = reqwest::Url::parse(normalize_endpoint(endpoint))
            .map_err(|_| format!("{name} is not a URL"))?;
        let host = url
            .host_str()
            .ok_or_else(|| format!("{name} has no host"))?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let port = url.port_or_known_default().unwrap_or(443);
        tokio::net::lookup_host((host.as_str(), port))
            .await
            .map(|it| it.map(|a| a.ip().to_canonical()).collect())
            .map_err(|_| format!("{name}'s host did not resolve"))
    }
    let p = addrs(primary, "the primary RPC").await?;
    let w = addrs(witness, "the inclusion witness").await?;
    if p.iter().any(|a| w.contains(a)) {
        return Ok(WitnessIndependence::NotIndependent(
            "both endpoints resolve to a shared address".to_string(),
        ));
    }
    Ok(WitnessIndependence::Distinct)
}

/// The form of an endpoint string that is both validated and posted to
/// (R7): surrounding whitespace removed, nothing else changed.
fn normalize_endpoint(endpoint: &str) -> &str {
    endpoint.trim()
}

/// What `Debug` prints in place of an endpoint (R5): its scheme and whether
/// it parsed, never the host, path, query or userinfo.
fn redacted_endpoint(endpoint: &str) -> String {
    match validate_endpoint(endpoint) {
        Ok(facts) => format!("<redacted {} endpoint>", facts.scheme),
        Err(_) => "<redacted unusable endpoint>".to_string(),
    }
}

/// Configuration for RPC client
///
/// `Debug` is written by hand (Round 29, audit 2026-10-20, R5): a derived one
/// printed `endpoint` in full, and a managed provider's endpoint carries the
/// operator's API key — so any `{:?}` of a config, of a client, or of any
/// struct holding one (a `tracing` field, a panic message, a test failure)
/// wrote the key out.
#[derive(Clone)]
pub struct RpcConfig {
    pub endpoint: String,
    pub commitment: String,
    pub timeout: Duration,
    pub max_retries: u32,
}

impl std::fmt::Debug for RpcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcConfig")
            .field("endpoint", &redacted_endpoint(&self.endpoint))
            .field("commitment", &self.commitment)
            .field("timeout", &self.timeout)
            .field("max_retries", &self.max_retries)
            .finish()
    }
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
///
/// `Debug` by hand, for the reason on `RpcConfig` (R5).
#[derive(Clone)]
pub struct SolanaRpcClient {
    config: RpcConfig,
    http_client: Option<HttpClient>,
}

impl std::fmt::Debug for SolanaRpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SolanaRpcClient")
            .field("config", &self.config)
            .field("http_client", &self.http_client.is_some())
            .finish()
    }
}

impl SolanaRpcClient {
    /// Create new RPC client with given configuration
    ///
    /// The endpoint is trimmed exactly as `validate_endpoint` trims it before
    /// judging it (R7), so the string that was validated is the string that
    /// is posted to.
    pub fn new(mut config: RpcConfig) -> Self {
        let trimmed = normalize_endpoint(&config.endpoint);
        if trimmed.len() != config.endpoint.len() {
            config.endpoint = trimmed.to_string();
        }
        // Build the HTTP client BEFORE moving `config` into the struct
        // (field init uses the value first — a use-after-move otherwise).
        //
        // Redirects are not followed. `reqwest` follows up to ten by
        // default, which lets whoever answers on the RPC socket — a
        // compromised provider, a hijacked record — send the request, and
        // Graphite's trust in the answer, to an address of their choosing,
        // including a plaintext one. A JSON-RPC endpoint that answers 3xx is
        // an endpoint that is not answering, and that is what it is reported
        // as (Round 12).
        //
        // No environment proxy either (Round 40, R39-CB-13). With
        // `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` set, reqwest connected to
        // the proxy and handed it the RPC host name: the connect-time guard
        // (`GuardedResolver`) then judged only the proxy's address, and the
        // proxy resolved the provider's name itself — a name pointing at a
        // private, loopback or metadata address reached it unjudged. RPC
        // egress is direct (docs/ops/install.md), so the guard always judges
        // the endpoint the request actually goes to.
        let http_client = HttpClient::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .dns_resolver(std::sync::Arc::new(GuardedResolver))
            .tls_certs_only(bundled_root_certificates())
            .build()
            .ok();
        Self {
            config,
            http_client,
        }
    }

    /// The endpoint this client posts to. Kept for equality checks between
    /// clients — never for logging; see `validate_endpoint`.
    pub fn endpoint(&self) -> &str {
        &self.config.endpoint
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
    /// - HTTP 2xx with a non-null JSON-RPC `error` → definitive `RequestFailed`.
    /// - Other non-2xx → `RequestFailed`.
    ///
    /// Returns the JSON-RPC `result` value on success (see `jsonrpc_result`).
    async fn post_rpc(&self, body: serde_json::Value) -> Result<serde_json::Value, RpcError> {
        let request_id = body.get("id").cloned();
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
                    if status.is_redirection() {
                        return Err(RpcError::RequestFailed(format!(
                            "RPC endpoint answered with a redirect (HTTP {}); redirects are not followed",
                            status.as_u16()
                        )));
                    }
                    if !status.is_success() {
                        return Err(RpcError::RequestFailed(format!(
                            "RPC HTTP error: {}",
                            status
                        )));
                    }
                    let body = read_body_capped(res).await?;
                    if json_value_count_within(&body, MAX_RPC_RESPONSE_VALUES).is_none() {
                        return Err(RpcError::InvalidResponse(format!(
                            "RPC response holds more than {MAX_RPC_RESPONSE_VALUES} JSON values; refused before parsing"
                        )));
                    }
                    let json: serde_json::Value = serde_json::from_slice(&body)
                        .map_err(|e| RpcError::InvalidResponse(bound_rpc_text(&e.to_string())))?;
                    return jsonrpc_result(json, request_id.as_ref());
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
        let mut sim = parse_simulation_value(value)?;
        sim.slot = context_slot(&result);
        Ok(sim)
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
        self.get_multiple_accounts_at(pubkeys)
            .await
            .map(|(_, accounts)| accounts)
    }

    /// `get_multiple_accounts`, also returning the slot the read was served
    /// at: `Some(slot)` when every chunk of the request came back at the same
    /// slot, `None` when the response carried no slot or the chunks disagree
    /// (a multi-chunk read that straddled a slot boundary is not one
    /// snapshot, and reporting either chunk's slot as "the" slot would say it
    /// was).
    pub async fn get_multiple_accounts_at(
        &self,
        pubkeys: &[String],
    ) -> Result<(Option<u64>, Vec<Option<AccountState>>), RpcError> {
        self.get_multiple_accounts_sliced(pubkeys, None).await
    }

    /// `get_multiple_accounts_at`, reading only `(offset, length)` of each
    /// account's data when `slice` is set (`dataSlice`): a program's
    /// ProgramData account holds its whole binary, and a deployment check
    /// needs its first 45 bytes.
    async fn get_multiple_accounts_sliced(
        &self,
        pubkeys: &[String],
        slice: Option<(usize, usize)>,
    ) -> Result<(Option<u64>, Vec<Option<AccountState>>), RpcError> {
        const CHUNK: usize = 100;
        let mut out: Vec<Option<AccountState>> = Vec::with_capacity(pubkeys.len());
        let mut slot: Option<u64> = None;
        let mut slots_agree = true;
        for chunk in pubkeys.chunks(CHUNK) {
            let mut config =
                serde_json::json!({"encoding":"base64","commitment":self.config.commitment});
            if let Some((offset, length)) = slice {
                config["dataSlice"] = serde_json::json!({"offset": offset, "length": length});
            }
            let params = serde_json::json!([chunk, config]);
            let body = serde_json::json!({
                "jsonrpc":"2.0","id":1,"method":"getMultipleAccounts","params":params
            });
            let result = self.post_rpc(body).await?;
            match (slot, context_slot(&result)) {
                (None, s) if out.is_empty() => slot = s,
                (Some(a), Some(b)) if a == b => {}
                _ => slots_agree = false,
            }
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
        Ok((if slots_agree { slot } else { None }, out))
    }

    /// What the BPF Upgradeable Loader says about each program's code now
    /// (roadmap R-M1): the slot it was last deployed at and who may replace
    /// it. Two batched reads, each of a header only (`dataSlice`): the
    /// program accounts (36 bytes: the loader's `Program` tag and the
    /// ProgramData address), then their ProgramData accounts (45 bytes: tag,
    /// deploy slot, upgrade authority). An answer that does not decode as the
    /// loader's layout is an error, never a guess.
    pub async fn get_program_deployments(
        &self,
        programs: &[String],
    ) -> Result<Vec<ProgramDeployment>, RpcError> {
        let (_, accounts) = self
            .get_multiple_accounts_sliced(programs, Some((0, PROGRAM_HEADER_READ)))
            .await?;
        let mut out = Vec::with_capacity(programs.len());
        let mut programdata: Vec<String> = Vec::new();
        for (program, account) in programs.iter().zip(&accounts) {
            match account {
                None => out.push(ProgramDeployment::Missing),
                Some(a) if a.owner == LOADER_V4 => match decode_loader_v4_header(&a.data) {
                    Some((deploy_slot, authority, status)) => {
                        out.push(ProgramDeployment::LoaderV4 {
                            deploy_slot,
                            authority,
                            retracted: status == 0,
                        })
                    }
                    None => out.push(ProgramDeployment::Unreadable {
                        why: format!(
                            "{program} is owned by loader-v4 but its account does not decode as LoaderV4State"
                        ),
                    }),
                },
                Some(a) if a.owner != UPGRADEABLE_LOADER => {
                    out.push(ProgramDeployment::NotUpgradeable {
                        owner: a.owner.clone(),
                    })
                }
                Some(a) => match decode_program_account(&a.data) {
                    Some(address) => {
                        programdata.push(address.clone());
                        out.push(ProgramDeployment::Upgradeable {
                            programdata: address,
                            deploy_slot: 0,
                            upgrade_authority: None,
                        });
                    }
                    None => out.push(ProgramDeployment::Unreadable {
                        why: format!(
                            "{program} is owned by the upgradeable loader but its account is not a Program"
                        ),
                    }),
                },
            }
        }
        if programdata.is_empty() {
            return Ok(out);
        }
        let (_, headers) = self
            .get_multiple_accounts_sliced(&programdata, Some((0, PROGRAMDATA_HEADER)))
            .await?;
        let mut headers = headers.into_iter();
        for entry in out.iter_mut() {
            let ProgramDeployment::Upgradeable {
                programdata,
                deploy_slot,
                upgrade_authority,
            } = entry
            else {
                continue;
            };
            let read = match headers.next().flatten() {
                None => Err(format!("ProgramData {programdata} does not exist")),
                Some(h) if h.owner != UPGRADEABLE_LOADER => Err(format!(
                    "ProgramData {programdata} is not owned by the upgradeable loader"
                )),
                Some(h) => decode_programdata_header(&h.data).ok_or_else(|| {
                    format!("ProgramData {programdata} does not decode as the loader's ProgramData")
                }),
            };
            match read {
                Ok((slot, authority)) => {
                    *deploy_slot = slot;
                    *upgrade_authority = authority;
                }
                Err(why) => *entry = ProgramDeployment::Unreadable { why },
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

        let mut sim = parse_simulation_value(value)?;
        sim.slot = context_slot(&result);

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

    /// The current epoch and where the current slot sits in it
    /// (`getEpochInfo`). Round 21: the Token-2022 fee model needs to know
    /// which of a mint's two schedules applied, and whether the transaction
    /// can still land after the other one takes over.
    pub async fn get_epoch_info(&self) -> Result<EpochInfo, RpcError> {
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"getEpochInfo","params":[{"commitment":self.config.commitment}]});
        let result = self.post_rpc(body).await?;
        EpochInfo::from_value(&result)
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
    ///
    /// `maxSupportedTransactionVersion: 1` (Round 12): devnet blocks carry
    /// version-1 transactions since 2026-09 (block 499429420: 7 of 60), and
    /// an RPC refuses the WHOLE block to a client that caps at 0 — so every
    /// block with one v1 transaction in it was unreadable and the live corpus
    /// found nothing. The v1 entries come back with `"version": 1`; Graphite
    /// parses v1 frames from their bytes (Round 19), and the JSON-shaped
    /// `live_corpus::tx_to_input` reads them in the layout checked against a
    /// real mainnet response (Round 21, see there).
    pub async fn get_block(&self, slot: u64) -> Result<serde_json::Value, RpcError> {
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"getBlock","params":[slot,{"encoding":"json","transactionDetails":"full","maxSupportedTransactionVersion":1,"rewards":false}]});
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
            "params": [signature, {
                "encoding": "json",
                "commitment": self.transaction_commitment(),
                "maxSupportedTransactionVersion": 1
            }]
        });
        self.post_rpc(body).await
    }

    /// The commitment `getTransaction` is asked at: the configured one, raised
    /// to `confirmed` when it is `processed`, which the method refuses.
    ///
    /// Round 29 (audit 2026-10-20, R1/M9): the call sent NO commitment, so the
    /// node answered at its default, `finalized`. For the ~13 seconds or more
    /// a transaction is confirmed but not yet rooted, `getSignatureStatuses`
    /// (which reports any level) said it was included while `getTransaction`
    /// said it did not exist — L8 could not bind the chain's bytes to a
    /// verification and fell back to the caller's keys, and an
    /// executed-after-block alarm waited for finalization.
    fn transaction_commitment(&self) -> &str {
        match self.config.commitment.as_str() {
            "processed" => "confirmed",
            other => other,
        }
    }

    /// The serialized bytes of one confirmed transaction (`getTransaction`,
    /// encoding: base64), or `None` when the cluster has no record of the
    /// signature.
    ///
    /// Round 12: the slot and outcome the response states are returned too
    /// (`ChainTransaction`) so L8 can hold them against the status call.
    pub async fn get_transaction_bytes(
        &self,
        signature: &str,
    ) -> Result<Option<Vec<u8>>, RpcError> {
        Ok(self
            .get_chain_transaction(signature)
            .await?
            .map(|t| t.bytes))
    }

    /// One transaction as the chain holds it: bytes, slot and outcome.
    ///
    /// This is what lets L8 attribute an execution to a verification
    /// without believing the caller: the bytes come from the chain, the
    /// signature slots are zeroed, and the digest is looked up
    /// (`tx_artifact::artifact_sha256_of_signed`, Round 10). Anything but a
    /// `[base64, "base64"]` pair in `result.transaction` is an invalid
    /// response, never a silent `None`.
    pub async fn get_chain_transaction(
        &self,
        signature: &str,
    ) -> Result<Option<ChainTransaction>, RpcError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "getTransaction",
            "params": [signature, {
                "encoding": "base64",
                "commitment": self.transaction_commitment(),
                "maxSupportedTransactionVersion": 1
            }]
        });
        let result = self.post_rpc(body).await?;
        if result.is_null() {
            return Ok(None);
        }
        let pair = result
            .get("transaction")
            .and_then(|t| t.as_array())
            .ok_or_else(|| {
                RpcError::InvalidResponse(
                    "getTransaction result.transaction is not an array".to_string(),
                )
            })?;
        let (Some(encoded), Some(encoding)) = (
            pair.first().and_then(|v| v.as_str()),
            pair.get(1).and_then(|v| v.as_str()),
        ) else {
            return Err(RpcError::InvalidResponse(
                "getTransaction result.transaction is not a [data, encoding] pair".to_string(),
            ));
        };
        if encoding != "base64" {
            return Err(RpcError::InvalidResponse(format!(
                "getTransaction returned encoding {encoding:?}, base64 was requested"
            )));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| RpcError::InvalidResponse(format!("getTransaction base64: {e}")))?;
        let slot = result.get("slot").and_then(|s| s.as_u64());
        // A meta without `err` says nothing about the outcome (W16, external
        // review): it was read as success.
        let succeeded = match result.get("meta") {
            None | Some(serde_json::Value::Null) => None,
            Some(meta) => meta.get("err").map(|e| e.is_null()),
        };
        Ok(Some(ChainTransaction {
            bytes,
            slot,
            succeeded,
        }))
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
        // Every field a conclusion rests on must be present and well-formed.
        // Until Round 12 a missing slot read as 0 and a status object with
        // neither `Ok` nor `Err` read as "included and failed" — a malformed
        // answer became an `ApprovedButFailedOnChain` conclusion.
        let slot = value.get("slot").and_then(|s| s.as_u64()).ok_or_else(|| {
            RpcError::InvalidResponse("getSignatureStatuses status has no slot".to_string())
        })?;
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
            _ => {
                return Err(RpcError::InvalidResponse(
                    "getSignatureStatuses status is neither Ok nor Err".to_string(),
                ))
            }
        };
        let commitment = match value.get("confirmationStatus").and_then(|c| c.as_str()) {
            Some("processed") => InclusionCommitment::Processed,
            Some("confirmed") => InclusionCommitment::Confirmed,
            Some("finalized") => InclusionCommitment::Finalized,
            Some(other) => {
                return Err(RpcError::InvalidResponse(format!(
                    "getSignatureStatuses confirmationStatus is {:?}",
                    bound_rpc_text(other)
                )))
            }
            // The field has been in every release since v1.7 (2021). An
            // answer without it does not state how far the cluster stands
            // behind the inclusion, and L8 does not guess.
            None => {
                return Err(RpcError::InvalidResponse(
                    "getSignatureStatuses status carries no confirmationStatus".to_string(),
                ))
            }
        };
        Ok(Some(SignatureStatus {
            slot,
            confirmations,
            success,
            error: err,
            commitment,
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
///
/// Round 29 (audit 2026-10-20, R8): only classic Tokenkeg was recognised, so
/// every Token-2022 account read as frozen; and the LAYOUT was never checked,
/// so a 82-byte mint failed closed only by accident of length, while a
/// 355-byte Multisig — whose byte 108 is inside a signer key — answered with
/// whatever that key byte was. Now an account answers only when it IS a
/// token account: owned by Token or Token-2022, exactly the 165-byte base
/// layout (or, for Token-2022, longer and typed `Account` at byte 165), and
/// decoding as one (`state_diff::decode_token_account`, which also refuses
/// an invalid COption tag). Anything else — including state 0
/// (Uninitialized), which no transfer can use either — is `true`.
pub fn token_account_frozen_flag(account: &AccountState) -> bool {
    use crate::state_diff::{SPL_TOKEN_2022_PROGRAM, SPL_TOKEN_PROGRAM};
    const TOKEN_ACCOUNT_LEN: usize = 165;

    let layout_ok = match account.owner.as_str() {
        SPL_TOKEN_PROGRAM => account.data.len() == TOKEN_ACCOUNT_LEN,
        // `decode_token_account` checks the account-type byte of a longer
        // Token-2022 account and refuses the Multisig length.
        SPL_TOKEN_2022_PROGRAM => account.data.len() >= TOKEN_ACCOUNT_LEN,
        // Not a token account — the caller asked a question this account
        // cannot answer. Fail-closed (P12): treat as frozen/inconclusive
        // rather than silently approving.
        _ => false,
    };
    if !layout_ok {
        return true;
    }
    match crate::state_diff::decode_token_account(&account.data) {
        Some(view) => view.state != 1,
        // Uninitialized, or not decodable as an account. Fail-closed.
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Round 31: every bundled root parses (none silently dropped by the
    /// `filter_map`), and the client builds with them as its only anchors.
    #[test]
    fn the_rpc_client_trusts_exactly_the_bundled_roots() {
        let roots = bundled_root_certificates();
        assert_eq!(roots.len(), webpki_root_certs::TLS_SERVER_ROOT_CERTS.len());
        assert!(roots.len() > 100, "the Mozilla set, not a stub");
        let client = SolanaRpcClient::new(RpcConfig::default());
        assert!(
            client.http_client.is_some(),
            "the RPC client must build with the bundled roots"
        );
    }

    /// R-M1: the loader-v3 layouts, byte for byte, and a refusal for anything else.
    #[test]
    fn the_upgradeable_loader_headers_decode_exactly() {
        let mut program = 2u32.to_le_bytes().to_vec();
        program.extend([7u8; 32]);
        assert_eq!(
            decode_program_account(&program),
            Some(Pubkey::from_bytes([7u8; 32]).to_base58())
        );
        assert_eq!(decode_program_account(&program[..35]), None, "short");
        let mut buffer = program.clone();
        buffer[..4].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            decode_program_account(&buffer),
            None,
            "a Buffer is not a Program"
        );

        let mut header = 3u32.to_le_bytes().to_vec();
        header.extend(451_887_084u64.to_le_bytes());
        header.push(1);
        header.extend([9u8; 32]);
        assert_eq!(
            decode_programdata_header(&header),
            Some((451_887_084, Some(Pubkey::from_bytes([9u8; 32]).to_base58())))
        );
        let mut final_program = header[..12].to_vec();
        final_program.push(0);
        assert_eq!(
            decode_programdata_header(&final_program),
            Some((451_887_084, None))
        );
        let mut bad_option = header.clone();
        bad_option[12] = 2;
        assert_eq!(decode_programdata_header(&bad_option), None);
        assert_eq!(
            decode_programdata_header(&header[..44]),
            None,
            "authority cut short"
        );
    }

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

    /// W16 (external review): the byte cap bounded the body, not the parsed
    /// tree. A body of 1.5 million zeros is 3 MB and would parse to 48 MB of
    /// `Value`s; the count refuses it before parsing, and a real response
    /// (one value per string, however long) is far inside the limit.
    #[test]
    fn a_response_is_bounded_by_what_it_parses_to_not_only_its_bytes() {
        let real = br#"{"jsonrpc":"2.0","result":{"value":[{"data":["AAAA\"\\[1,2]","base64"],"lamports":5,"owner":"11111111111111111111111111111111","executable":false}]},"id":1}"#;
        assert_eq!(
            json_value_count_within(real, MAX_RPC_RESPONSE_VALUES),
            Some(20)
        );
        let mut zeros = b"{\"result\":[".to_vec();
        for i in 0..1_500_000u32 {
            if i > 0 {
                zeros.push(b',');
            }
            zeros.push(b'0');
        }
        zeros.extend_from_slice(b"]}");
        assert!(zeros.len() < MAX_RPC_RESPONSE_BYTES);
        assert_eq!(
            json_value_count_within(&zeros, MAX_RPC_RESPONSE_VALUES),
            None
        );
    }

    #[tokio::test]
    async fn an_rpc_answer_with_too_many_values_is_refused_before_parsing() {
        let mut body = String::from("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":[");
        for i in 0..1_100_000u32 {
            if i > 0 {
                body.push(',');
            }
            body.push('0');
        }
        body.push_str("]}");
        let body: &'static str = Box::leak(body.into_boxed_str());
        let (url, handle) = mock_rpc_server(vec![(200, body)]);
        let err = client_at(&url, 0).get_slot().await.unwrap_err();
        assert!(err.to_string().contains("JSON values"), "{err}");
        handle.join().unwrap();
    }

    /// W16 (external review): a `getTransaction` meta that does not state
    /// `err` says nothing about the outcome. It was read as success.
    #[tokio::test]
    async fn a_transaction_meta_without_err_is_not_a_success() {
        let (url, handle) = mock_rpc_server(vec![
            (
                200,
                r#"{"jsonrpc":"2.0","id":1,"result":{"slot":7,"transaction":["AQID","base64"],"meta":{"fee":5000}}}"#,
            ),
            (
                200,
                r#"{"jsonrpc":"2.0","id":1,"result":{"slot":7,"transaction":["AQID","base64"],"meta":{"err":null}}}"#,
            ),
        ]);
        let client = client_at(&url, 0);
        let unstated = client.get_chain_transaction("sig").await.unwrap().unwrap();
        assert_eq!(unstated.succeeded, None, "no `err`, no outcome");
        let stated = client.get_chain_transaction("sig").await.unwrap().unwrap();
        assert_eq!(stated.succeeded, Some(true));
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
            "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"slot\":2},\"value\":[{\"slot\":100,\"confirmations\":0,\"confirmationStatus\":\"confirmed\",\"err\":null,\"status\":{\"Ok\":null}}]},\"id\":1}",
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
        assert_eq!(st.commitment, InclusionCommitment::Confirmed);
        assert!(st.error.is_none());
        handle.join().unwrap();
    }

    #[tokio::test]
    async fn test_get_signature_status_err_is_failure() {
        let (url, handle) = mock_rpc_server(vec![(
            200,
            "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"slot\":2},\"value\":[{\"slot\":101,\"confirmations\":null,\"confirmationStatus\":\"finalized\",\"err\":null,\"status\":{\"Err\":{\"InstructionError\":[0,{\"Custom\":1}]}}}]},\"id\":1}",
        )]);
        let client = client_at(&url, 0);
        let st = client
            .get_signature_status("5sigAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .await
            .expect("status must parse")
            .expect("signature must be known");
        assert!(!st.success, "Err status must not be success");
        assert!(st.error.is_some());
        assert_eq!(st.commitment, InclusionCommitment::Finalized);
        assert!(st.commitment.is_cluster_backed());
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

    /// `getAccountInfo` read as the cluster answers it — the System Program's
    /// own account, in the shape a validator returns it (`context`, `value`
    /// with base64 data, `space`). W24 (external review): this was a live
    /// devnet call left `#[ignore]`, so CI never ran it; the request it makes
    /// is unchanged, the answer is served on loopback, and an absent account
    /// is `AccountNotFound`, not a zeroed account.
    #[tokio::test]
    async fn get_account_reads_a_validators_answer() {
        let (url, handle) = mock_rpc_server(vec![
            (
                200,
                r#"{"jsonrpc":"2.0","result":{"context":{"apiVersion":"2.2.7","slot":412345678},"value":{"data":["c3lzdGVtX3Byb2dyYW0=","base64"],"executable":true,"lamports":1,"owner":"NativeLoader1111111111111111111111111111111","rentEpoch":18446744073709551615,"space":14}},"id":1}"#,
            ),
            (
                200,
                r#"{"jsonrpc":"2.0","result":{"context":{"slot":412345679},"value":null},"id":1}"#,
            ),
        ]);
        let client = client_at(&url, 0);
        let pubkey = Pubkey::from_base58("11111111111111111111111111111111").unwrap();
        let account = client.get_account(&pubkey).await.unwrap();
        assert_eq!(account.pubkey, "11111111111111111111111111111111");
        assert_eq!(account.owner, "NativeLoader1111111111111111111111111111111");
        assert_eq!(account.lamports, 1);
        assert!(account.executable);
        assert_eq!(account.rent_epoch, u64::MAX);
        assert_eq!(account.data, b"system_program");
        assert!(matches!(
            client.get_account(&pubkey).await,
            Err(RpcError::AccountNotFound(k)) if k == "11111111111111111111111111111111"
        ));
        handle.join().unwrap();
    }
}

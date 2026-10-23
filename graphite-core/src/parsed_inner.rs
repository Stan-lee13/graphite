//! The bytes behind an inner instruction that an RPC reported in parsed form
//! (Round 35).
//!
//! Agave's `simulateTransaction` never returns an inner instruction in the
//! compiled form (`programIdIndex`, account indexes, base58 data). Every one
//! is run through `solana_transaction_status::parse_ui_instruction`: an
//! instruction of a program Agave knows how to parse comes back as
//! `{program, programId, parsed: {type, info}, stackHeight}`, anything else as
//! `{programId, accounts: [<address>…], data, stackHeight}`. Graphite read only
//! the compiled form, so on a real RPC every transaction that made a CPI ended
//! `VerificationIncomplete` ("the simulator's report of the programs this
//! transaction called could not be read") and could never be approved. Found by
//! the live mainnet runs on Round 34's code (23 of 200 replayed transactions,
//! 24 of 200 in Round 32's run).
//!
//! The partially decoded form carries everything and is read as is. This
//! module rebuilds the parsed form: the account list and instruction data a
//! System, SPL Token / Token-2022 or Associated Token Account instruction must
//! have had for Agave to print exactly that JSON. Each rebuilt instruction is
//! the canonical encoding of what the program decoded: Agave's parsers decode
//! with the programs' own instruction types, which ignore trailing data bytes
//! and accounts past the ones they read, and print every account the program
//! reads by position. Accounts a program does not read (a System transfer's
//! third account, a legacy ATA `Create`'s rent sysvar) are not in the JSON and
//! not in the rebuilt list.
//!
//! What is not rebuilt is `None`, and the caller treats the inner-instruction
//! report as unread, as before: every other parsed program (Memo, whose JSON
//! drops its signer accounts; the loaders; Stake; Vote; lookup tables), the
//! Token-2022 extension instructions, `batch`, `allocateWithSeed` and
//! `assignWithSeed` (their second account is not printed and is not the
//! `base` in the data), and any `info` whose keys are not exactly the ones
//! Agave prints for its type. The reader is strict on purpose: a field it does
//! not expect may carry something the bytes would have said.
//!
//! `tools/inner-instruction-oracle` checks every rebuild against Agave's own
//! parser: random instructions of every supported type are packed with the
//! programs' interface crates, parsed by `solana-transaction-status`, rebuilt
//! here, and must come back byte for byte and account for account.

use serde_json::{Map, Value};

pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
pub const SPL_TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const SPL_TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
pub const ASSOCIATED_TOKEN_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

/// The accounts (addresses, in instruction order) and data of an inner
/// instruction reported as `{program, programId, parsed, …}`, or `None` when
/// this module does not rebuild it exactly.
pub fn rebuild(program_id: &str, parsed: &Value) -> Option<(Vec<String>, Vec<u8>)> {
    let parsed = parsed.as_object()?;
    // `{type, info}`; Agave omits `info` when it is null.
    if !parsed.keys().all(|k| k == "type" || k == "info") {
        return None;
    }
    let kind = parsed.get("type")?.as_str()?;
    let empty = Map::new();
    let info = match parsed.get("info") {
        None => &empty,
        Some(v) => v.as_object()?,
    };
    match program_id {
        SYSTEM_PROGRAM => system(kind, info),
        SPL_TOKEN_PROGRAM | SPL_TOKEN_2022_PROGRAM => token(kind, info),
        ASSOCIATED_TOKEN_PROGRAM => associated_token(kind, info),
        _ => None,
    }
}

/// `info` holds exactly `required`, plus any of `optional`.
fn keys(info: &Map<String, Value>, required: &[&str], optional: &[&str]) -> bool {
    required.iter().all(|k| info.contains_key(*k))
        && info
            .keys()
            .all(|k| required.contains(&k.as_str()) || optional.contains(&k.as_str()))
}

fn address(info: &Map<String, Value>, key: &str) -> Option<String> {
    let s = info.get(key)?.as_str()?;
    pubkey(s)?;
    Some(s.to_string())
}

fn pubkey(s: &str) -> Option<[u8; 32]> {
    let bytes = bs58::decode(s).into_vec().ok()?;
    let key: [u8; 32] = bytes.try_into().ok()?;
    // The canonical spelling only: one key, one string.
    (bs58::encode(key).into_string() == s).then_some(key)
}

fn pubkey_at(info: &Map<String, Value>, key: &str) -> Option<[u8; 32]> {
    pubkey(info.get(key)?.as_str()?)
}

/// A JSON number that is a u64 (System amounts are printed as numbers).
fn number_u64(info: &Map<String, Value>, key: &str) -> Option<u64> {
    info.get(key)?.as_u64()
}

/// A decimal string that is a u64 (Token amounts are printed as strings).
fn string_u64(v: &Value) -> Option<u64> {
    let s = v.as_str()?;
    // `u64::to_string` never prints a sign, a leading zero or a space.
    if s.is_empty() || (s.len() > 1 && s.starts_with('0')) || !s.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    s.parse().ok()
}

fn u8_at(info: &Map<String, Value>, key: &str) -> Option<u8> {
    u8::try_from(info.get(key)?.as_u64()?).ok()
}

/// bincode 1 (fixint) of a `String`: a u64 length, then the bytes.
fn push_string(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u64).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

fn system(kind: &str, info: &Map<String, Value>) -> Option<(Vec<String>, Vec<u8>)> {
    let tag = |t: u32| t.to_le_bytes().to_vec();
    let a = |k: &str| address(info, k);
    match kind {
        "createAccount" => {
            if !keys(
                info,
                &["source", "newAccount", "lamports", "space", "owner"],
                &[],
            ) {
                return None;
            }
            let mut d = tag(0);
            d.extend_from_slice(&number_u64(info, "lamports")?.to_le_bytes());
            d.extend_from_slice(&number_u64(info, "space")?.to_le_bytes());
            d.extend_from_slice(&pubkey_at(info, "owner")?);
            Some((vec![a("source")?, a("newAccount")?], d))
        }
        "assign" => {
            if !keys(info, &["account", "owner"], &[]) {
                return None;
            }
            let mut d = tag(1);
            d.extend_from_slice(&pubkey_at(info, "owner")?);
            Some((vec![a("account")?], d))
        }
        "transfer" => {
            if !keys(info, &["source", "destination", "lamports"], &[]) {
                return None;
            }
            let mut d = tag(2);
            d.extend_from_slice(&number_u64(info, "lamports")?.to_le_bytes());
            Some((vec![a("source")?, a("destination")?], d))
        }
        "createAccountWithSeed" => {
            let req = [
                "source",
                "newAccount",
                "base",
                "seed",
                "lamports",
                "space",
                "owner",
            ];
            if !keys(info, &req, &[]) {
                return None;
            }
            let mut d = tag(3);
            d.extend_from_slice(&pubkey_at(info, "base")?);
            push_string(&mut d, info.get("seed")?.as_str()?);
            d.extend_from_slice(&number_u64(info, "lamports")?.to_le_bytes());
            d.extend_from_slice(&number_u64(info, "space")?.to_le_bytes());
            d.extend_from_slice(&pubkey_at(info, "owner")?);
            Some((vec![a("source")?, a("newAccount")?], d))
        }
        "advanceNonce" => {
            let req = ["nonceAccount", "recentBlockhashesSysvar", "nonceAuthority"];
            if !keys(info, &req, &[]) {
                return None;
            }
            let accounts = req.iter().map(|k| a(k)).collect::<Option<Vec<_>>>()?;
            Some((accounts, tag(4)))
        }
        "withdrawFromNonce" => {
            let order = [
                "nonceAccount",
                "destination",
                "recentBlockhashesSysvar",
                "rentSysvar",
                "nonceAuthority",
            ];
            let mut req = order.to_vec();
            req.push("lamports");
            if !keys(info, &req, &[]) {
                return None;
            }
            let mut d = tag(5);
            d.extend_from_slice(&number_u64(info, "lamports")?.to_le_bytes());
            let accounts = order.iter().map(|k| a(k)).collect::<Option<Vec<_>>>()?;
            Some((accounts, d))
        }
        "initializeNonce" => {
            let order = ["nonceAccount", "recentBlockhashesSysvar", "rentSysvar"];
            let mut req = order.to_vec();
            req.push("nonceAuthority");
            if !keys(info, &req, &[]) {
                return None;
            }
            let mut d = tag(6);
            d.extend_from_slice(&pubkey_at(info, "nonceAuthority")?);
            let accounts = order.iter().map(|k| a(k)).collect::<Option<Vec<_>>>()?;
            Some((accounts, d))
        }
        "authorizeNonce" => {
            if !keys(
                info,
                &["nonceAccount", "nonceAuthority", "newAuthorized"],
                &[],
            ) {
                return None;
            }
            let mut d = tag(7);
            d.extend_from_slice(&pubkey_at(info, "newAuthorized")?);
            Some((vec![a("nonceAccount")?, a("nonceAuthority")?], d))
        }
        "allocate" => {
            if !keys(info, &["account", "space"], &[]) {
                return None;
            }
            let mut d = tag(8);
            d.extend_from_slice(&number_u64(info, "space")?.to_le_bytes());
            Some((vec![a("account")?], d))
        }
        "transferWithSeed" => {
            let order = ["source", "sourceBase", "destination"];
            let mut req = order.to_vec();
            req.extend(["lamports", "sourceSeed", "sourceOwner"]);
            if !keys(info, &req, &[]) {
                return None;
            }
            let mut d = tag(11);
            d.extend_from_slice(&number_u64(info, "lamports")?.to_le_bytes());
            push_string(&mut d, info.get("sourceSeed")?.as_str()?);
            d.extend_from_slice(&pubkey_at(info, "sourceOwner")?);
            let accounts = order.iter().map(|k| a(k)).collect::<Option<Vec<_>>>()?;
            Some((accounts, d))
        }
        "upgradeNonce" => {
            if !keys(info, &["nonceAccount"], &[]) {
                return None;
            }
            Some((vec![a("nonceAccount")?], tag(12)))
        }
        "createAccountAllowPrefund" => {
            let lamports = number_u64(info, "lamports").unwrap_or(0);
            let mut d = tag(13);
            d.extend_from_slice(&lamports.to_le_bytes());
            d.extend_from_slice(&number_u64(info, "space")?.to_le_bytes());
            d.extend_from_slice(&pubkey_at(info, "owner")?);
            if info.contains_key("lamports") {
                // With a funder: `lamports` is printed only when non-zero.
                if lamports == 0
                    || !keys(
                        info,
                        &["newAccount", "source", "lamports", "space", "owner"],
                        &[],
                    )
                {
                    return None;
                }
                Some((vec![a("newAccount")?, a("source")?], d))
            } else {
                if !keys(info, &["newAccount", "space", "owner"], &[]) {
                    return None;
                }
                Some((vec![a("newAccount")?], d))
            }
        }
        // `allocateWithSeed` and `assignWithSeed`: the instruction's second
        // account is not printed (the `base` shown is the data's), so the
        // account list cannot be rebuilt.
        _ => None,
    }
}

/// The authority of a Token instruction: `owner_key` alone, or
/// `multisig_key` followed by `signers` (Agave's `parse_signers`).
fn token_authority(
    info: &Map<String, Value>,
    owner_key: &str,
    multisig_key: &str,
) -> Option<Vec<String>> {
    if info.contains_key(owner_key) {
        if info.contains_key(multisig_key) || info.contains_key("signers") {
            return None;
        }
        Some(vec![address(info, owner_key)?])
    } else {
        let mut out = vec![address(info, multisig_key)?];
        let signers = info.get("signers")?.as_array()?;
        // `parse_signers` prints the multisig form only with at least one
        // signer after it.
        if signers.is_empty() {
            return None;
        }
        for s in signers {
            let s = s.as_str()?;
            pubkey(s)?;
            out.push(s.to_string());
        }
        Some(out)
    }
}

/// `tokenAmount` as `token_amount_to_ui_amount_v3` prints it; only `amount`
/// and `decimals` are read, the UI forms are derived from them.
fn token_amount(v: &Value) -> Option<(u64, u8)> {
    let o = v.as_object()?;
    if !keys(o, &["amount", "decimals"], &["uiAmount", "uiAmountString"]) {
        return None;
    }
    Some((
        string_u64(o.get("amount")?)?,
        u8::try_from(o.get("decimals")?.as_u64()?).ok()?,
    ))
}

/// The u8 Token-2022 gives each `AuthorityType`, by the camelCase name Agave
/// prints.
fn authority_type(name: &str) -> Option<u8> {
    const NAMES: [&str; 18] = [
        "mintTokens",
        "freezeAccount",
        "accountOwner",
        "closeAccount",
        "transferFeeConfig",
        "withheldWithdraw",
        "closeMint",
        "interestRate",
        "permanentDelegate",
        "confidentialTransferMint",
        "transferHookProgramId",
        "confidentialTransferFeeConfig",
        "metadataPointer",
        "groupPointer",
        "groupMemberPointer",
        "scaledUiAmount",
        "pause",
        "permissionedBurn",
    ];
    NAMES.iter().position(|n| *n == name).map(|i| i as u8)
}

/// The u16 Token-2022 gives each `ExtensionType`, by the camelCase name Agave
/// prints (`UiExtensionType`).
fn extension_type(name: &str) -> Option<u16> {
    const NAMES: [&str; 29] = [
        "uninitialized",
        "transferFeeConfig",
        "transferFeeAmount",
        "mintCloseAuthority",
        "confidentialTransferMint",
        "confidentialTransferAccount",
        "defaultAccountState",
        "immutableOwner",
        "memoTransfer",
        "nonTransferable",
        "interestBearingConfig",
        "cpiGuard",
        "permanentDelegate",
        "nonTransferableAccount",
        "transferHook",
        "transferHookAccount",
        "confidentialTransferFeeConfig",
        "confidentialTransferFeeAmount",
        "metadataPointer",
        "tokenMetadata",
        "groupPointer",
        "tokenGroup",
        "groupMemberPointer",
        "tokenGroupMember",
        "confidentialMintBurn",
        "scaledUiAmount",
        "pausable",
        "pausableAccount",
        "permissionedBurn",
    ];
    NAMES.iter().position(|n| *n == name).map(|i| i as u16)
}

/// `pack_pubkey_option`: 0, or 1 and the key.
fn push_pubkey_option(buf: &mut Vec<u8>, v: Option<&Value>) -> Option<()> {
    match v {
        None | Some(Value::Null) => buf.push(0),
        Some(s) => {
            buf.push(1);
            buf.extend_from_slice(&pubkey(s.as_str()?)?);
        }
    }
    Some(())
}

fn token(kind: &str, info: &Map<String, Value>) -> Option<(Vec<String>, Vec<u8>)> {
    let a = |k: &str| address(info, k);
    // Instructions shaped `fixed accounts…, authority or multisig + signers`.
    let with_authority =
        |fixed: &[&str], other: &[&str], owner: &str, multisig: &str| -> Option<Vec<String>> {
            let mut req: Vec<&str> = fixed.to_vec();
            req.extend_from_slice(other);
            let opt = [owner, multisig, "signers"];
            if !keys(info, &req, &opt) {
                return None;
            }
            let mut accounts = fixed.iter().map(|k| a(k)).collect::<Option<Vec<_>>>()?;
            accounts.extend(token_authority(info, owner, multisig)?);
            Some(accounts)
        };
    let amount_le = |k: &str| -> Option<[u8; 8]> { Some(string_u64(info.get(k)?)?.to_le_bytes()) };
    match kind {
        "initializeMint" | "initializeMint2" => {
            let two = kind == "initializeMint2";
            let req: &[&str] = if two {
                &["mint", "decimals", "mintAuthority"]
            } else {
                &["mint", "decimals", "mintAuthority", "rentSysvar"]
            };
            if !keys(info, req, &["freezeAuthority"]) {
                return None;
            }
            let mut d = vec![if two { 20 } else { 0 }, u8_at(info, "decimals")?];
            d.extend_from_slice(&pubkey_at(info, "mintAuthority")?);
            // Printed only when set; `null` is never printed.
            match info.get("freezeAuthority") {
                Some(Value::Null) => return None,
                v => push_pubkey_option(&mut d, v)?,
            }
            let mut accounts = vec![a("mint")?];
            if !two {
                accounts.push(a("rentSysvar")?);
            }
            Some((accounts, d))
        }
        "initializeAccount" => {
            let order = ["account", "mint", "owner", "rentSysvar"];
            if !keys(info, &order, &[]) {
                return None;
            }
            let accounts = order.iter().map(|k| a(k)).collect::<Option<Vec<_>>>()?;
            Some((accounts, vec![1]))
        }
        "initializeAccount2" | "initializeAccount3" => {
            let two = kind == "initializeAccount2";
            let req: &[&str] = if two {
                &["account", "mint", "owner", "rentSysvar"]
            } else {
                &["account", "mint", "owner"]
            };
            if !keys(info, req, &[]) {
                return None;
            }
            let mut d = vec![if two { 16 } else { 18 }];
            d.extend_from_slice(&pubkey_at(info, "owner")?);
            let mut accounts = vec![a("account")?, a("mint")?];
            if two {
                accounts.push(a("rentSysvar")?);
            }
            Some((accounts, d))
        }
        "initializeMultisig" | "initializeMultisig2" => {
            let two = kind == "initializeMultisig2";
            let req: &[&str] = if two {
                &["multisig", "signers", "m"]
            } else {
                &["multisig", "rentSysvar", "signers", "m"]
            };
            if !keys(info, req, &[]) {
                return None;
            }
            let mut accounts = vec![a("multisig")?];
            if !two {
                accounts.push(a("rentSysvar")?);
            }
            let signers = info.get("signers")?.as_array()?;
            if signers.is_empty() {
                // `check_num_token_accounts` needs at least one signer account.
                return None;
            }
            for s in signers {
                let s = s.as_str()?;
                pubkey(s)?;
                accounts.push(s.to_string());
            }
            Some((accounts, vec![if two { 19 } else { 2 }, u8_at(info, "m")?]))
        }
        "transfer" => {
            let accounts = with_authority(
                &["source", "destination"],
                &["amount"],
                "authority",
                "multisigAuthority",
            )?;
            let mut d = vec![3];
            d.extend_from_slice(&amount_le("amount")?);
            Some((accounts, d))
        }
        "approve" => {
            let accounts = with_authority(
                &["source", "delegate"],
                &["amount"],
                "owner",
                "multisigOwner",
            )?;
            let mut d = vec![4];
            d.extend_from_slice(&amount_le("amount")?);
            Some((accounts, d))
        }
        "revoke" => {
            let accounts = with_authority(&["source"], &[], "owner", "multisigOwner")?;
            Some((accounts, vec![5]))
        }
        "setAuthority" => {
            // The owned account is `mint` or `account`, by authority type.
            let ty = info.get("authorityType")?.as_str()?;
            let code = authority_type(ty)?;
            let owned = if code == 2 || code == 3 {
                "account"
            } else {
                "mint"
            };
            let accounts = with_authority(
                &[owned],
                &["authorityType", "newAuthority"],
                "authority",
                "multisigAuthority",
            )?;
            let mut d = vec![6, code];
            push_pubkey_option(&mut d, info.get("newAuthority"))?;
            Some((accounts, d))
        }
        "mintTo" => {
            let accounts = with_authority(
                &["mint", "account"],
                &["amount"],
                "mintAuthority",
                "multisigMintAuthority",
            )?;
            let mut d = vec![7];
            d.extend_from_slice(&amount_le("amount")?);
            Some((accounts, d))
        }
        "burn" => {
            let accounts = with_authority(
                &["account", "mint"],
                &["amount"],
                "authority",
                "multisigAuthority",
            )?;
            let mut d = vec![8];
            d.extend_from_slice(&amount_le("amount")?);
            Some((accounts, d))
        }
        "closeAccount" => {
            let accounts =
                with_authority(&["account", "destination"], &[], "owner", "multisigOwner")?;
            Some((accounts, vec![9]))
        }
        "freezeAccount" | "thawAccount" => {
            let accounts = with_authority(
                &["account", "mint"],
                &[],
                "freezeAuthority",
                "multisigFreezeAuthority",
            )?;
            Some((
                accounts,
                vec![if kind == "freezeAccount" { 10 } else { 11 }],
            ))
        }
        "transferChecked" | "approveChecked" | "mintToChecked" | "burnChecked" => {
            let (tag, fixed, owner, multisig): (u8, &[&str], &str, &str) = match kind {
                "transferChecked" => (
                    12,
                    &["source", "mint", "destination"],
                    "authority",
                    "multisigAuthority",
                ),
                "approveChecked" => (
                    13,
                    &["source", "mint", "delegate"],
                    "owner",
                    "multisigOwner",
                ),
                "mintToChecked" => (
                    14,
                    &["mint", "account"],
                    "mintAuthority",
                    "multisigMintAuthority",
                ),
                _ => (15, &["account", "mint"], "authority", "multisigAuthority"),
            };
            let accounts = with_authority(fixed, &["tokenAmount"], owner, multisig)?;
            let (amount, decimals) = token_amount(info.get("tokenAmount")?)?;
            let mut d = vec![tag];
            d.extend_from_slice(&amount.to_le_bytes());
            d.push(decimals);
            Some((accounts, d))
        }
        "syncNative" | "initializeImmutableOwner" | "initializeNonTransferableMint" => {
            let (key, tag) = match kind {
                "syncNative" => ("account", 17),
                "initializeImmutableOwner" => ("account", 22),
                _ => ("mint", 32),
            };
            if !keys(info, &[key], &[]) {
                return None;
            }
            Some((vec![a(key)?], vec![tag]))
        }
        "getAccountDataSize" => {
            if !keys(info, &["mint"], &["extensionTypes"]) {
                return None;
            }
            let mut d = vec![21];
            if let Some(types) = info.get("extensionTypes") {
                let types = types.as_array()?;
                // Printed only when non-empty.
                if types.is_empty() {
                    return None;
                }
                for t in types {
                    d.extend_from_slice(&extension_type(t.as_str()?)?.to_le_bytes());
                }
            }
            Some((vec![a("mint")?], d))
        }
        "amountToUiAmount" => {
            if !keys(info, &["mint", "amount"], &[]) {
                return None;
            }
            let mut d = vec![23];
            d.extend_from_slice(&amount_le("amount")?);
            Some((vec![a("mint")?], d))
        }
        "uiAmountToAmount" => {
            if !keys(info, &["mint", "uiAmount"], &[]) {
                return None;
            }
            let mut d = vec![24];
            d.extend_from_slice(info.get("uiAmount")?.as_str()?.as_bytes());
            Some((vec![a("mint")?], d))
        }
        "initializeMintCloseAuthority" => {
            if !keys(info, &["mint", "newAuthority"], &[]) {
                return None;
            }
            let mut d = vec![25];
            push_pubkey_option(&mut d, info.get("newAuthority"))?;
            Some((vec![a("mint")?], d))
        }
        "createNativeMint" => {
            let order = ["payer", "nativeMint", "systemProgram"];
            if !keys(info, &order, &[]) {
                return None;
            }
            let accounts = order.iter().map(|k| a(k)).collect::<Option<Vec<_>>>()?;
            Some((accounts, vec![31]))
        }
        "initializePermanentDelegate" => {
            if !keys(info, &["mint", "delegate"], &[]) {
                return None;
            }
            let mut d = vec![35];
            d.extend_from_slice(&pubkey_at(info, "delegate")?);
            Some((vec![a("mint")?], d))
        }
        "withdrawExcessLamports" => {
            let accounts = with_authority(
                &["source", "destination"],
                &[],
                "authority",
                "multisigAuthority",
            )?;
            Some((accounts, vec![38]))
        }
        "unwrapLamports" => {
            if !keys(
                info,
                &["source", "destination"],
                &["amount", "authority", "multisigAuthority", "signers"],
            ) {
                return None;
            }
            let mut accounts = vec![a("source")?, a("destination")?];
            accounts.extend(token_authority(info, "authority", "multisigAuthority")?);
            let mut d = vec![45];
            match info.get("amount") {
                None => d.push(0),
                Some(v) => {
                    d.push(1);
                    d.extend_from_slice(&string_u64(v)?.to_le_bytes());
                }
            }
            Some((accounts, d))
        }
        // The extension instructions, `batch`, token-group and
        // token-metadata instructions: not rebuilt.
        _ => None,
    }
}

fn associated_token(kind: &str, info: &Map<String, Value>) -> Option<(Vec<String>, Vec<u8>)> {
    let (order, data): (&[&str], u8) = match kind {
        "create" => (
            &[
                "source",
                "account",
                "wallet",
                "mint",
                "systemProgram",
                "tokenProgram",
            ],
            0,
        ),
        "createIdempotent" => (
            &[
                "source",
                "account",
                "wallet",
                "mint",
                "systemProgram",
                "tokenProgram",
            ],
            1,
        ),
        "recoverNested" => (
            &[
                "nestedSource",
                "nestedMint",
                "destination",
                "nestedOwner",
                "ownerMint",
                "wallet",
                "tokenProgram",
            ],
            2,
        ),
        _ => return None,
    };
    if !keys(info, order, &[]) {
        return None;
    }
    let accounts = order
        .iter()
        .map(|k| address(info, k))
        .collect::<Option<Vec<_>>>()?;
    // `create` is printed for both an empty data and `[0]`; the borsh form is
    // what today's builders send and decodes to the same instruction.
    Some((accounts, vec![data]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const A: &str = "4cvyjjocbsVgYLsJGsy1UmVZHi4XYtagv38zezydqzSx";
    const B: &str = "8HBQFrsUGdm5PmwbBLKt4re6AHaDuv7aVFqzArj2hHtk";
    const C: &str = "So11111111111111111111111111111111111111112";

    #[test]
    fn a_system_transfer_is_rebuilt_byte_for_byte() {
        let (accounts, data) = rebuild(
            SYSTEM_PROGRAM,
            &json!({"type": "transfer", "info": {"source": A, "destination": B, "lamports": 5000}}),
        )
        .unwrap();
        assert_eq!(accounts, vec![A, B]);
        let mut want = 2u32.to_le_bytes().to_vec();
        want.extend_from_slice(&5000u64.to_le_bytes());
        assert_eq!(data, want);
    }

    #[test]
    fn a_token_transfer_checked_reads_amount_and_decimals_only() {
        let parsed = json!({"type": "transferChecked", "info": {
            "source": A, "mint": C, "destination": B, "authority": A,
            "tokenAmount": {"amount": "1500", "decimals": 6, "uiAmount": 0.0015, "uiAmountString": "0.0015"}}});
        let (accounts, data) = rebuild(SPL_TOKEN_PROGRAM, &parsed).unwrap();
        assert_eq!(accounts, vec![A, C, B, A]);
        let mut want = vec![12];
        want.extend_from_slice(&1500u64.to_le_bytes());
        want.push(6);
        assert_eq!(data, want);
    }

    #[test]
    fn a_multisig_authority_keeps_its_signers_in_order() {
        let parsed = json!({"type": "transfer", "info": {
            "source": A, "destination": B, "amount": "7", "multisigAuthority": C, "signers": [B, A]}});
        let (accounts, _) = rebuild(SPL_TOKEN_2022_PROGRAM, &parsed).unwrap();
        assert_eq!(accounts, vec![A, B, C, B, A]);
    }

    #[test]
    fn anything_unexpected_is_not_rebuilt() {
        // An unknown key, a missing key, both authority forms, a non-canonical
        // amount, an unknown type, an unparsed program.
        for (program, parsed) in [
            (
                SYSTEM_PROGRAM,
                json!({"type": "transfer", "info": {"source": A, "destination": B, "lamports": 1, "note": "x"}}),
            ),
            (
                SYSTEM_PROGRAM,
                json!({"type": "transfer", "info": {"source": A, "lamports": 1}}),
            ),
            (
                SPL_TOKEN_PROGRAM,
                json!({"type": "transfer", "info": {"source": A, "destination": B, "amount": "1", "authority": A, "multisigAuthority": C, "signers": [B]}}),
            ),
            (
                SPL_TOKEN_PROGRAM,
                json!({"type": "transfer", "info": {"source": A, "destination": B, "amount": "01", "authority": A}}),
            ),
            (
                SPL_TOKEN_PROGRAM,
                json!({"type": "transfer", "info": {"source": A, "destination": B, "amount": 1, "authority": A}}),
            ),
            (
                SPL_TOKEN_PROGRAM,
                json!({"type": "transferCheckedWithFee", "info": {}}),
            ),
            (
                SYSTEM_PROGRAM,
                json!({"type": "allocateWithSeed", "info": {"account": A, "base": B, "seed": "s", "space": 1, "owner": C}}),
            ),
            (
                "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
                json!("hello"),
            ),
            (
                SYSTEM_PROGRAM,
                json!({"type": "transfer", "info": {"source": "not-a-key", "destination": B, "lamports": 1}}),
            ),
            (
                SYSTEM_PROGRAM,
                json!({"type": "transfer", "info": {"source": A, "destination": B, "lamports": 1}, "extra": 1}),
            ),
        ] {
            assert!(rebuild(program, &parsed).is_none(), "{program} {parsed}");
        }
    }
}

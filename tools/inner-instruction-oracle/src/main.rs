//! Graphite's rebuild of parsed inner instructions, against Agave's parser.
//!
//! `simulateTransaction` reports every inner instruction through
//! `solana_transaction_status::parse_ui_instruction` (Round 35). For random
//! System, SPL Token / Token-2022 and Associated Token Account instructions,
//! packed by the programs' own interface crates, this runs that parser, hands
//! its JSON to `graphite_core::parsed_inner::rebuild`, and requires:
//!
//! - **Round trip**: the rebuilt accounts and data, parsed again, print
//!   exactly the JSON the RPC printed. A rebuild that prints differently is a
//!   rebuild of some other instruction.
//! - **Exactness**: for an instruction in canonical form (the accounts the
//!   program reads, no trailing bytes), the rebuild is the original, byte for
//!   byte and account for account.
//! - **Coverage**: every type Graphite claims to rebuild was rebuilt, and no
//!   such type was ever refused.
//!
//! Random data and extra accounts (`--fuzz` share of iterations) exercise the
//! round trip on whatever Agave accepts.
//!
//! `--emit-fixture PATH` writes a sample of (JSON, rebuilt accounts, data) for
//! `graphite-core/tests/round35_parsed_inner_instructions.rs`, so the core's
//! own test suite carries Agave's real output without depending on Agave.

use graphite_core::parsed_inner::rebuild;
use serde_json::{json, Value};
use solana_message::{compiled_instruction::CompiledInstruction, AccountKeys};
use solana_program_option::COption;
use solana_pubkey::Pubkey;
use solana_system_interface::instruction::SystemInstruction;
use solana_transaction_status::parse_ui_instruction;
use spl_token_2022_interface::extension::ExtensionType;
use spl_token_2022_interface::instruction::{AuthorityType, TokenInstruction};
use std::collections::BTreeMap;

const SYSTEM: &str = "11111111111111111111111111111111";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const ATA: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

/// The types `parsed_inner` rebuilds, by program. A parsed instruction of one
/// of these that is not rebuilt is a failure.
const SYSTEM_TYPES: &[&str] = &[
    "createAccount",
    "assign",
    "transfer",
    "createAccountWithSeed",
    "advanceNonce",
    "withdrawFromNonce",
    "initializeNonce",
    "authorizeNonce",
    "allocate",
    "transferWithSeed",
    "upgradeNonce",
    "createAccountAllowPrefund",
];
const TOKEN_TYPES: &[&str] = &[
    "initializeMint",
    "initializeMint2",
    "initializeAccount",
    "initializeAccount2",
    "initializeAccount3",
    "initializeMultisig",
    "initializeMultisig2",
    "transfer",
    "approve",
    "revoke",
    "setAuthority",
    "mintTo",
    "burn",
    "closeAccount",
    "freezeAccount",
    "thawAccount",
    "transferChecked",
    "approveChecked",
    "mintToChecked",
    "burnChecked",
    "syncNative",
    "getAccountDataSize",
    "initializeImmutableOwner",
    "amountToUiAmount",
    "uiAmountToAmount",
    "initializeMintCloseAuthority",
    "createNativeMint",
    "initializeNonTransferableMint",
    "initializePermanentDelegate",
    "withdrawExcessLamports",
    "unwrapLamports",
];
const ATA_TYPES: &[&str] = &["create", "createIdempotent", "recoverNested"];

/// xorshift64*: deterministic per seed, no dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn coin(&mut self) -> bool {
        self.next() & 1 == 1
    }
    fn amount(&mut self) -> u64 {
        match self.below(4) {
            0 => 0,
            1 => u64::MAX,
            2 => self.below(1_000_000),
            _ => self.next(),
        }
    }
    fn key(&mut self) -> Pubkey {
        let mut b = [0u8; 32];
        for chunk in b.chunks_mut(8) {
            chunk.copy_from_slice(&self.next().to_le_bytes());
        }
        Pubkey::new_from_array(b)
    }
    fn seed(&mut self) -> String {
        let n = self.below(33) as usize;
        (0..n)
            .map(|_| (b'a' + self.below(26) as u8) as char)
            .collect()
    }
}

/// One generated instruction: the program, its accounts (indexes into the key
/// pool) and data, and whether it is in canonical form.
struct Case {
    program: &'static str,
    accounts: Vec<u8>,
    data: Vec<u8>,
    canonical: bool,
}

const POOL: usize = 24;

fn idx(r: &mut Rng, n: usize) -> Vec<u8> {
    (0..n).map(|_| r.below(POOL as u64) as u8).collect()
}

fn system_case(r: &mut Rng, keys: &[Pubkey]) -> Case {
    let k = |r: &mut Rng| keys[r.below(POOL as u64) as usize];
    let (ix, n) = match r.below(12) {
        0 => (
            SystemInstruction::CreateAccount {
                lamports: r.amount(),
                space: r.amount(),
                owner: k(r),
            },
            2,
        ),
        1 => (SystemInstruction::Assign { owner: k(r) }, 1),
        2 => (
            SystemInstruction::Transfer {
                lamports: r.amount(),
            },
            2,
        ),
        3 => (
            SystemInstruction::CreateAccountWithSeed {
                base: k(r),
                seed: r.seed(),
                lamports: r.amount(),
                space: r.amount(),
                owner: k(r),
            },
            2,
        ),
        4 => (SystemInstruction::AdvanceNonceAccount, 3),
        5 => (SystemInstruction::WithdrawNonceAccount(r.amount()), 5),
        6 => (SystemInstruction::InitializeNonceAccount(k(r)), 3),
        7 => (SystemInstruction::AuthorizeNonceAccount(k(r)), 2),
        8 => (SystemInstruction::Allocate { space: r.amount() }, 1),
        9 => (
            SystemInstruction::TransferWithSeed {
                lamports: r.amount(),
                from_seed: r.seed(),
                from_owner: k(r),
            },
            3,
        ),
        10 => (SystemInstruction::UpgradeNonceAccount, 1),
        _ => {
            let lamports = if r.coin() { 0 } else { r.amount().max(1) };
            (
                SystemInstruction::CreateAccountAllowPrefund {
                    lamports,
                    space: r.amount(),
                    owner: k(r),
                },
                if lamports == 0 { 1 } else { 2 },
            )
        }
    };
    Case {
        program: SYSTEM,
        accounts: idx(r, n),
        data: bincode::serialize(&ix).expect("bincode"),
        canonical: true,
    }
}

fn coption_key(r: &mut Rng, keys: &[Pubkey]) -> COption<Pubkey> {
    if r.coin() {
        COption::Some(keys[r.below(POOL as u64) as usize])
    } else {
        COption::None
    }
}

const EXTENSIONS: [ExtensionType; 29] = [
    ExtensionType::Uninitialized,
    ExtensionType::TransferFeeConfig,
    ExtensionType::TransferFeeAmount,
    ExtensionType::MintCloseAuthority,
    ExtensionType::ConfidentialTransferMint,
    ExtensionType::ConfidentialTransferAccount,
    ExtensionType::DefaultAccountState,
    ExtensionType::ImmutableOwner,
    ExtensionType::MemoTransfer,
    ExtensionType::NonTransferable,
    ExtensionType::InterestBearingConfig,
    ExtensionType::CpiGuard,
    ExtensionType::PermanentDelegate,
    ExtensionType::NonTransferableAccount,
    ExtensionType::TransferHook,
    ExtensionType::TransferHookAccount,
    ExtensionType::ConfidentialTransferFeeConfig,
    ExtensionType::ConfidentialTransferFeeAmount,
    ExtensionType::MetadataPointer,
    ExtensionType::TokenMetadata,
    ExtensionType::GroupPointer,
    ExtensionType::TokenGroup,
    ExtensionType::GroupMemberPointer,
    ExtensionType::TokenGroupMember,
    ExtensionType::ConfidentialMintBurn,
    ExtensionType::ScaledUiAmount,
    ExtensionType::Pausable,
    ExtensionType::PausableAccount,
    ExtensionType::PermissionedBurn,
];

const AUTHORITIES: [AuthorityType; 18] = [
    AuthorityType::MintTokens,
    AuthorityType::FreezeAccount,
    AuthorityType::AccountOwner,
    AuthorityType::CloseAccount,
    AuthorityType::TransferFeeConfig,
    AuthorityType::WithheldWithdraw,
    AuthorityType::CloseMint,
    AuthorityType::InterestRate,
    AuthorityType::PermanentDelegate,
    AuthorityType::ConfidentialTransferMint,
    AuthorityType::TransferHookProgramId,
    AuthorityType::ConfidentialTransferFeeConfig,
    AuthorityType::MetadataPointer,
    AuthorityType::GroupPointer,
    AuthorityType::GroupMemberPointer,
    AuthorityType::ScaledUiAmount,
    AuthorityType::Pause,
    AuthorityType::PermissionedBurn,
];

fn token_case(r: &mut Rng, keys: &[Pubkey], ui: &mut String) -> Case {
    // `fixed` accounts, then (when `auth`) an owner or a multisig with signers.
    let program = if r.coin() { TOKEN } else { TOKEN_2022 };
    let amount = r.amount();
    let decimals = r.below(256) as u8;
    let (ix, fixed, auth): (TokenInstruction, usize, bool) = match r.below(31) {
        0 => (
            TokenInstruction::InitializeMint {
                decimals,
                mint_authority: keys[r.below(POOL as u64) as usize],
                freeze_authority: coption_key(r, keys),
            },
            2,
            false,
        ),
        1 => (
            TokenInstruction::InitializeMint2 {
                decimals,
                mint_authority: keys[r.below(POOL as u64) as usize],
                freeze_authority: coption_key(r, keys),
            },
            1,
            false,
        ),
        2 => (TokenInstruction::InitializeAccount, 4, false),
        3 => (
            TokenInstruction::InitializeAccount2 {
                owner: keys[r.below(POOL as u64) as usize],
            },
            3,
            false,
        ),
        4 => (
            TokenInstruction::InitializeAccount3 {
                owner: keys[r.below(POOL as u64) as usize],
            },
            2,
            false,
        ),
        5 => (
            TokenInstruction::InitializeMultisig {
                m: r.below(12) as u8,
            },
            2 + 1 + r.below(10) as usize,
            false,
        ),
        6 => (
            TokenInstruction::InitializeMultisig2 {
                m: r.below(12) as u8,
            },
            1 + 1 + r.below(10) as usize,
            false,
        ),
        #[allow(deprecated)]
        7 => (TokenInstruction::Transfer { amount }, 2, true),
        8 => (TokenInstruction::Approve { amount }, 2, true),
        9 => (TokenInstruction::Revoke, 1, true),
        10 => (
            TokenInstruction::SetAuthority {
                authority_type: AUTHORITIES[r.below(18) as usize].clone(),
                new_authority: coption_key(r, keys),
            },
            1,
            true,
        ),
        11 => (TokenInstruction::MintTo { amount }, 2, true),
        12 => (TokenInstruction::Burn { amount }, 2, true),
        13 => (TokenInstruction::CloseAccount, 2, true),
        14 => (TokenInstruction::FreezeAccount, 2, true),
        15 => (TokenInstruction::ThawAccount, 2, true),
        16 => (
            TokenInstruction::TransferChecked { amount, decimals },
            3,
            true,
        ),
        17 => (
            TokenInstruction::ApproveChecked { amount, decimals },
            3,
            true,
        ),
        18 => (
            TokenInstruction::MintToChecked { amount, decimals },
            2,
            true,
        ),
        19 => (TokenInstruction::BurnChecked { amount, decimals }, 2, true),
        20 => (TokenInstruction::SyncNative, 1, false),
        21 => {
            let n = r.below(4) as usize;
            let extension_types = (0..n).map(|_| EXTENSIONS[r.below(29) as usize]).collect();
            (
                TokenInstruction::GetAccountDataSize { extension_types },
                1,
                false,
            )
        }
        22 => (TokenInstruction::InitializeImmutableOwner, 1, false),
        23 => (TokenInstruction::AmountToUiAmount { amount }, 1, false),
        24 => {
            *ui = match r.below(4) {
                0 => String::new(),
                1 => format!("{}", amount),
                2 => format!("{}.{}", r.below(1000), r.below(1_000_000)),
                _ => r.seed(),
            };
            (
                TokenInstruction::UiAmountToAmount {
                    ui_amount: ui.as_str(),
                },
                1,
                false,
            )
        }
        25 => (
            TokenInstruction::InitializeMintCloseAuthority {
                close_authority: coption_key(r, keys),
            },
            1,
            false,
        ),
        26 => (TokenInstruction::CreateNativeMint, 3, false),
        27 => (TokenInstruction::InitializeNonTransferableMint, 1, false),
        28 => (
            TokenInstruction::InitializePermanentDelegate {
                delegate: keys[r.below(POOL as u64) as usize],
            },
            1,
            false,
        ),
        29 => (TokenInstruction::WithdrawExcessLamports, 2, true),
        _ => (
            TokenInstruction::UnwrapLamports {
                amount: if r.coin() {
                    COption::Some(amount)
                } else {
                    COption::None
                },
            },
            2,
            true,
        ),
    };
    let n = fixed
        + if auth {
            1 + if r.below(4) == 0 {
                1 + r.below(11) as usize
            } else {
                0
            }
        } else {
            0
        };
    Case {
        program,
        accounts: idx(r, n),
        data: ix.pack(),
        canonical: true,
    }
}

fn ata_case(r: &mut Rng) -> Case {
    let (data, n) = match r.below(3) {
        0 => (vec![0], 6),
        1 => (vec![1], 6),
        _ => (vec![2], 7),
    };
    Case {
        program: ATA,
        accounts: idx(r, n),
        data,
        canonical: true,
    }
}

/// Random bytes, or a canonical case with extra accounts or trailing bytes:
/// only the round trip is required of these.
fn fuzz_case(r: &mut Rng, keys: &[Pubkey], ui: &mut String) -> Case {
    let mut c = match r.below(3) {
        0 => system_case(r, keys),
        1 => token_case(r, keys, ui),
        _ => ata_case(r),
    };
    c.canonical = false;
    match r.below(3) {
        0 => {
            let n = 1 + r.below(4) as usize;
            c.accounts.extend(idx(r, n));
        }
        1 => c.data.extend((0..1 + r.below(16)).map(|_| r.next() as u8)),
        _ => {
            let n = r.below(80) as usize;
            c.data = (0..n).map(|_| r.next() as u8).collect();
            if r.coin() && !c.data.is_empty() {
                c.data[0] = r.below(48) as u8;
            }
            let n = r.below(12) as usize;
            c.accounts = idx(r, n);
        }
    }
    c
}

fn ui_json(program: &Pubkey, accounts: &[u8], data: &[u8], keys: &[Pubkey]) -> Value {
    let mut all = keys.to_vec();
    all.push(*program);
    let ci = CompiledInstruction {
        program_id_index: (all.len() - 1) as u8,
        accounts: accounts.to_vec(),
        data: data.to_vec(),
    };
    serde_json::to_value(parse_ui_instruction(
        &ci,
        &AccountKeys::new(&all, None),
        Some(2),
    ))
    .expect("serialize")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let iterations: u64 = arg("--iterations")
        .map(|s| s.parse().expect("--iterations"))
        .unwrap_or(200_000);
    let seed: u64 = arg("--seed")
        .map(|s| s.parse().expect("--seed"))
        .unwrap_or(20_261_023);
    let fuzz_share: u64 = arg("--fuzz-percent")
        .map(|s| s.parse().expect("--fuzz-percent"))
        .unwrap_or(30);
    let fixture = arg("--emit-fixture");

    let mut r = Rng(seed | 1);
    let keys: Vec<Pubkey> = (0..POOL).map(|_| r.key()).collect();
    let mut rebuilt: BTreeMap<String, u64> = BTreeMap::new();
    let mut refused: BTreeMap<String, u64> = BTreeMap::new();
    let mut failures: Vec<String> = Vec::new();
    let mut samples: Vec<Value> = Vec::new();
    let mut per_type_samples: BTreeMap<String, u32> = BTreeMap::new();
    let (mut parsed_n, mut partial_n) = (0u64, 0u64);

    for i in 0..iterations {
        let mut ui = String::new();
        let case = if r.below(100) < fuzz_share {
            fuzz_case(&mut r, &keys, &mut ui)
        } else {
            match r.below(10) {
                0..=3 => system_case(&mut r, &keys),
                4..=8 => token_case(&mut r, &keys, &mut ui),
                _ => ata_case(&mut r),
            }
        };
        let program: Pubkey = case.program.parse().expect("program id");
        let printed = ui_json(&program, &case.accounts, &case.data, &keys);
        let Some(parsed) = printed.get("parsed") else {
            partial_n += 1;
            continue;
        };
        parsed_n += 1;
        let kind = parsed
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("<no type>")
            .to_string();
        let label = format!("{}:{}", &case.program[..6], kind);
        let program_id = printed
            .get("programId")
            .and_then(Value::as_str)
            .expect("programId");
        assert_eq!(program_id, case.program);
        let supported = match case.program {
            SYSTEM => SYSTEM_TYPES.contains(&kind.as_str()),
            TOKEN | TOKEN_2022 => TOKEN_TYPES.contains(&kind.as_str()),
            _ => ATA_TYPES.contains(&kind.as_str()),
        };
        match rebuild(program_id, parsed) {
            None => {
                *refused.entry(label.clone()).or_default() += 1;
                if supported {
                    failures.push(format!(
                        "#{i} {label}: a supported type was not rebuilt: {printed}"
                    ));
                }
            }
            Some((accounts, data)) => {
                *rebuilt.entry(label.clone()).or_default() += 1;
                if !supported {
                    failures.push(format!(
                        "#{i} {label}: rebuilt a type the oracle does not cover: {printed}"
                    ));
                }
                let indexes: Option<Vec<u8>> = accounts
                    .iter()
                    .map(|a| {
                        keys.iter()
                            .position(|k| k.to_string() == *a)
                            .map(|p| p as u8)
                    })
                    .collect();
                let Some(indexes) = indexes else {
                    failures.push(format!(
                        "#{i} {label}: rebuilt an account outside the transaction: {accounts:?}"
                    ));
                    continue;
                };
                let again = ui_json(&program, &indexes, &data, &keys);
                if again != printed {
                    failures.push(format!(
                        "#{i} {label}: round trip differs\n  rpc     {printed}\n  rebuilt {again}"
                    ));
                    continue;
                }
                if case.canonical {
                    let original: Vec<String> = case
                        .accounts
                        .iter()
                        .map(|x| keys[*x as usize].to_string())
                        .collect();
                    // An ATA `create` is printed for both an empty data and
                    // `[0]`; the generator sends `[0]`.
                    if accounts != original || data != case.data {
                        failures.push(format!(
                            "#{i} {label}: not the original\n  accounts {original:?}\n  rebuilt  {accounts:?}\n  data     {:?}\n  rebuilt  {data:?}",
                            case.data
                        ));
                        continue;
                    }
                }
                let n = per_type_samples.entry(label.clone()).or_default();
                if fixture.is_some() && *n < 3 && case.canonical {
                    *n += 1;
                    samples.push(json!({"inner": printed, "accounts": accounts, "data": data}));
                }
            }
        }
        if failures.len() >= 20 {
            break;
        }
    }

    // Coverage: each supported type, on each token program, was rebuilt.
    let mut missing = Vec::new();
    for (prefix, types) in [
        ("111111", SYSTEM_TYPES),
        ("Tokenk", TOKEN_TYPES),
        ("Tokenz", TOKEN_TYPES),
        ("ATokenG", ATA_TYPES),
    ] {
        let prefix = &prefix[..6];
        for t in types {
            if rebuilt.get(&format!("{prefix}:{t}")).copied().unwrap_or(0) == 0 {
                missing.push(format!("{prefix}:{t}"));
            }
        }
    }
    println!(
        "iterations {iterations}, seed {seed}: parsed {parsed_n}, partially decoded {partial_n}"
    );
    println!("rebuilt by type:");
    for (k, v) in &rebuilt {
        println!("  {v:>8}  {k}");
    }
    println!("not rebuilt (Agave parsed, Graphite leaves unknown):");
    for (k, v) in &refused {
        println!("  {v:>8}  {k}");
    }
    if let Some(path) = fixture {
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&samples).expect("json") + "\n",
        )
        .expect("write fixture");
        println!("fixture: {} samples -> {path}", samples.len());
    }
    if !missing.is_empty() {
        failures.push(format!(
            "never rebuilt (raise --iterations or fix the generator): {missing:?}"
        ));
    }
    if !failures.is_empty() {
        for f in &failures {
            eprintln!("FAIL {f}");
        }
        std::process::exit(1);
    }
    println!("PASS: every rebuild round-trips through Agave's parser, every canonical one is the original");
}

//! Round 41 (D-23): Jupiter v6 `route_v2` and `shared_accounts_route_v2`,
//! decoded from the deployed program's committed IDL
//! (`scripts/out/onchain_idls/JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4.json`).
//!
//! Live run 41129142710: 8 of 13 Jupiter swaps used them, and every one was
//! unbound (`intent_parameters`), so never executable. The decode reads every
//! byte, with the `Swap` enum of the deployed program — which, from variant
//! 41 on, is not the enum of `scripts/idls/jupiter.json` the v1 decoder used.
//! The end-to-end parity and attack campaigns are in
//! `round41_live_false_refusals.rs`; these need no RPC and run in every leg.

use graphite_core::intent_binding::{
    decode_swap, JUPITER_CANDIDATE_SWAPS, JUPITER_SWAP_VARIANTS, JUPITER_V6,
};
use serde_json::Value;

const ONCHAIN_IDL: &str =
    include_str!("../scripts/out/onchain_idls/JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4.json");

fn idl() -> Value {
    serde_json::from_str(ONCHAIN_IDL).expect("the committed on-chain IDL parses")
}

fn type_named<'a>(idl: &'a Value, name: &str) -> &'a Value {
    idl["types"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == name)
        .unwrap_or_else(|| panic!("the IDL defines {name}"))
}

/// The token the decoder's tables use for one IDL field type.
fn token(idl: &Value, t: &Value) -> String {
    if let Some(s) = t.as_str() {
        return s.to_string();
    }
    if let Some(d) = t.get("defined") {
        let name = d["name"].as_str().unwrap();
        if name == "RemainingAccountsInfo" {
            return "rai".to_string();
        }
        let e = &type_named(idl, name)["type"];
        assert_eq!(e["kind"], "enum", "{name}");
        let variants = e["variants"].as_array().unwrap();
        assert!(
            variants.iter().all(|v| v.get("fields").is_none()),
            "{name} is a unit enum"
        );
        return format!("enum{}", variants.len());
    }
    if let Some(a) = t.get("array") {
        return format!("{}x{}", token(idl, &a[0]), a[1]);
    }
    if let Some(o) = t.get("option") {
        return format!("option<{}>", token(idl, o));
    }
    if let Some(v) = t.get("vec") {
        return match v["defined"]["name"].as_str().unwrap() {
            "CandidateSwap" => "vec<candidate>".to_string(),
            "CandidateSwapWithBps" => "vec<candidate_bps>".to_string(),
            other => panic!("unmapped vec of {other}"),
        };
    }
    panic!("unmapped type {t}");
}

/// The Core's `Swap` and `CandidateSwap` payload tables are the deployed
/// program's IDL, variant by variant.
#[test]
fn round41_the_jupiter_payload_tables_are_the_deployed_idls() {
    let idl = idl();
    for (name, table) in [
        ("Swap", &JUPITER_SWAP_VARIANTS[..]),
        ("CandidateSwap", &JUPITER_CANDIDATE_SWAPS[..]),
    ] {
        let variants = type_named(&idl, name)["type"]["variants"]
            .as_array()
            .unwrap();
        assert_eq!(table.len(), variants.len(), "{name}");
        for (i, v) in variants.iter().enumerate() {
            let want: Vec<String> = v
                .get("fields")
                .and_then(Value::as_array)
                .map(|f| f.iter().map(|f| token(&idl, &f["type"])).collect())
                .unwrap_or_default();
            let have: Vec<String> = table[i].iter().map(|s| s.to_string()).collect();
            assert_eq!(have, want, "{name} variant {i} {}", v["name"]);
        }
    }
    // The v2 arguments and step, as `jupiter_route_v2` reads them.
    let args = |ix: &str| -> Vec<(String, Value)> {
        idl["instructions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["name"] == ix)
            .unwrap()["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| (a["name"].as_str().unwrap().to_string(), a["type"].clone()))
            .collect()
    };
    let names = |ix: &str| -> Vec<String> { args(ix).into_iter().map(|(n, _)| n).collect() };
    assert_eq!(
        names("route_v2"),
        [
            "in_amount",
            "quoted_out_amount",
            "slippage_bps",
            "platform_fee_bps",
            "positive_slippage_bps",
            "route_plan"
        ]
    );
    assert_eq!(names("shared_accounts_route_v2")[0], "id");
    assert_eq!(
        names("shared_accounts_route_v2")[1..],
        names("route_v2")[..]
    );
    for (_, t) in args("route_v2").iter().take(5) {
        assert!(["u64", "u16"].contains(&t.as_str().unwrap()));
    }
    let step: Vec<(String, Value)> = type_named(&idl, "RoutePlanStepV2")["type"]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| (f["name"].as_str().unwrap().to_string(), f["type"].clone()))
        .collect();
    assert_eq!(
        step.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
        ["swap", "bps", "input_index", "output_index"]
    );
    assert_eq!(step[1].1, "u16");
    let disc = |ix: &str| -> String {
        let bytes: Vec<u8> = idl["instructions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["name"] == ix)
            .unwrap()["discriminator"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b.as_u64().unwrap() as u8)
            .collect();
        hex::encode(bytes)
    };
    assert_eq!(disc("route_v2"), "bb64facc31c4af14");
    assert_eq!(disc("shared_accounts_route_v2"), "d19853937cfed8e9");
}

fn v2(shared: bool, slippage: u16, platform: u16, positive: u16, plan: &[u8]) -> Vec<u8> {
    let mut d = hex::decode(if shared {
        "d19853937cfed8e9"
    } else {
        "bb64facc31c4af14"
    })
    .unwrap();
    if shared {
        d.push(0);
    }
    d.extend_from_slice(&1_000_000_000u64.to_le_bytes());
    d.extend_from_slice(&150_000_000u64.to_le_bytes());
    d.extend_from_slice(&slippage.to_le_bytes());
    d.extend_from_slice(&platform.to_le_bytes());
    d.extend_from_slice(&positive.to_le_bytes());
    d.extend_from_slice(plan);
    d
}

const ONE_STEP: [u8; 9] = [1, 0, 0, 0, 26, 0x10, 0x27, 0, 1];

/// A v2 route decodes to the amounts and minimum of its v1 twin; every
/// refusal the v1 route has, the v2 route has, and a positive-slippage fee
/// besides.
#[test]
fn round41_a_route_v2_reads_as_its_v1_twin_and_refuses_what_v1_refuses() {
    let mut v1 = hex::decode("e517cb977ae3ad2a").unwrap();
    v1.extend_from_slice(&[1, 0, 0, 0, 26, 100, 0, 1]);
    v1.extend_from_slice(&1_000_000_000u64.to_le_bytes());
    v1.extend_from_slice(&150_000_000u64.to_le_bytes());
    v1.extend_from_slice(&50u16.to_le_bytes());
    v1.push(0);
    let twin = decode_swap(JUPITER_V6, &v1).unwrap().unwrap();
    for shared in [false, true] {
        let d = decode_swap(JUPITER_V6, &v2(shared, 50, 0, 0, &ONE_STEP))
            .unwrap()
            .unwrap();
        assert_eq!((d.amount_in, d.min_out), (twin.amount_in, twin.min_out));
        assert_eq!(d.min_out, 149_250_000);
        let refused = |data: Vec<u8>, why: &str| {
            let e = decode_swap(JUPITER_V6, &data).unwrap().unwrap_err();
            assert!(e.contains(why), "shared={shared}: {e} (wanted {why})");
        };
        refused(v2(shared, 50, 1, 0, &ONE_STEP), "platform_fee_bps is 1");
        refused(
            v2(shared, 50, 0, 1, &ONE_STEP),
            "positive_slippage_bps is 1",
        );
        refused(v2(shared, 10_001, 0, 0, &ONE_STEP), "over 100%");
        refused(v2(shared, 50, 0, 0, &[0, 0, 0, 0]), "no steps");
        let mut trailing = v2(shared, 50, 0, 0, &ONE_STEP);
        trailing.push(0);
        refused(trailing, "follow the last argument");
        let mut short = v2(shared, 50, 0, 0, &ONE_STEP);
        short.pop();
        refused(short, "ends inside");
        refused(
            v2(shared, 50, 0, 0, &[1, 0, 0, 0, 188, 0x10, 0x27, 0, 1]),
            "Swap variant 188",
        );
        // Serum's Side is a two-variant enum.
        refused(
            v2(shared, 50, 0, 0, &[1, 0, 0, 0, 12, 2, 0x10, 0x27, 0, 1]),
            "enum tag 2",
        );
        // DynamicV1 naming CandidateSwap 17, past the IDL's 17.
        refused(
            v2(
                shared,
                50,
                0,
                0,
                &[1, 0, 0, 0, 111, 1, 0, 0, 0, 17, 0, 0x10, 0x27, 0, 1],
            ),
            "CandidateSwap variant 17",
        );
    }
    // DynamicV2 (146): two candidates, Whirlpool(a_to_b) and RaydiumClmm,
    // each with u32 bps, then two u8 — read to the end.
    let dynamic = [
        1, 0, 0, 0, 146, 2, 0, 0, 0, 5, 1, 0x88, 0x13, 0, 0, 4, 0x88, 0x13, 0, 0, 3, 3, 0x10, 0x27,
        0, 1,
    ];
    assert!(decode_swap(JUPITER_V6, &v2(false, 50, 0, 0, &dynamic))
        .unwrap()
        .is_ok());
}

/// The real mainnet `route_v2` committed with the pinned Jupiter fixture
/// (slot 438012579; `tests/fixtures/real_mainnet_jup.json`) reads to its
/// end. It carries a 150 bps platform fee, so it is refused for that — and
/// only that: with the fee field zeroed it decodes to its own amounts.
#[test]
fn round41_the_pinned_mainnet_route_v2_reads_to_its_end() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/real_mainnet_jup.json")).unwrap();
    let message = &fixture["transaction"]["message"];
    let keys: Vec<&str> = message["accountKeys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap())
        .collect();
    let route = message["instructions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|ix| keys[ix["programIdIndex"].as_u64().unwrap() as usize] == JUPITER_V6)
        .expect("the fixture's Jupiter instruction");
    let data = bs58::decode(route["data"].as_str().unwrap())
        .into_vec()
        .unwrap();
    assert_eq!(hex::encode(&data[..8]), "bb64facc31c4af14");
    let e = decode_swap(JUPITER_V6, &data).unwrap().unwrap_err();
    assert!(e.contains("platform_fee_bps is 150"), "{e}");
    let mut fee_free = data.clone();
    fee_free[26..28].copy_from_slice(&0u16.to_le_bytes());
    let d = decode_swap(JUPITER_V6, &fee_free).unwrap().unwrap();
    assert_eq!(d.amount_in, 2_200_000_000);
    assert_eq!(
        d.min_out,
        (85_363_099_743u128 * (10_000 - 900) / 10_000) as u64
    );
}

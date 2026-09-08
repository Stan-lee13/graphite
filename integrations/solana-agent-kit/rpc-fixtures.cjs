/**
 * Build Graphite VerificationInput fixtures backed by REAL devnet state.
 *
 * These exist so the live L3/L4 paths can be exercised end to end. Graphite
 * only builds its own RPC state diff when `signed_transaction` is present and
 * the simulation succeeds, so the blobs here have to be real transactions that
 * simulate cleanly against current devnet state.
 *
 * Nothing is signed and nothing is submitted. `simulateTransaction` defaults to
 * `sigVerify: false`, so a read-only simulation runs against real chain state
 * without a private key — which is the whole point: this is public-data
 * analysis, not a live action. The fee payer is the project's own Phase 1.5
 * devnet wallet named in ROADMAP.md; its balance is never altered because
 * nothing is ever sent.
 *
 * The blockhash must come from the `finalized` commitment: a `confirmed` one is
 * frequently not yet visible to the simulator and comes back BlockhashNotFound,
 * which makes the simulation error out and Graphite skip the diff (correctly,
 * but it looks like a bug in the harness).
 */
const fs = require("fs");
const path = require("path");
const web3 = require("@solana/web3.js");

const RPC = process.env.DEVNET_RPC || "https://api.devnet.solana.com";
const OUT = process.env.FIXTURE_DIR;
if (!OUT) {
  console.error("FIXTURE_DIR must be set (a scratch directory outside the repo)");
  process.exit(1);
}
fs.mkdirSync(OUT, { recursive: true });

// The project's own devnet test wallet (ROADMAP.md, Phase 1.5). Read-only use.
const FUNDED = new web3.PublicKey("CWb8MciizembLV66kisYcXo3Cb91hdszxw74QHpEJKZR");
const SYSTEM = "11111111111111111111111111111111";

function project(ix) {
  const data = Array.from(ix.data);
  const disc = Buffer.from(data.slice(0, 4)).toString("hex");
  return {
    program_id: ix.programId.toBase58(),
    instruction_discriminator: disc,
    account_addresses: ix.keys.map((k) => k.pubkey.toBase58()),
    instruction_data: data,
    real_account_metas: ix.keys.map((k) => ({
      pubkey: k.pubkey.toBase58(),
      is_signer: k.isSigner,
      is_writable: k.isWritable,
    })),
  };
}

function fixture(name, primaryIx, tx, extra = {}) {
  const p = project(primaryIx);
  return {
    __name: name,
    __expect: extra.expect || "",
    proposed_intent: {
      intent_type: extra.intent || "transfer",
      raw_natural_language: extra.text || "devnet fixture",
      confidence_of_parse: 0.95,
    },
    program_id: p.program_id,
    protocol_version: "1.0.0",
    instruction_discriminator: p.instruction_discriminator,
    account_addresses: p.account_addresses,
    instruction_data: p.instruction_data,
    real_account_metas: p.real_account_metas,
    wallet_profile: extra.profile || "Gaming",
    compute_units: extra.compute_units ?? 0,
    account_writes: p.real_account_metas.filter((m) => m.is_writable).length,
    cpi_hops: extra.cpi_hops ?? 0,
    signed_transaction: Array.from(
      tx.serialize({ requireAllSignatures: false, verifySignatures: false })
    ),
    ...(extra.transaction_instructions ? { transaction_instructions: extra.transaction_instructions } : {}),
  };
}

async function main() {
  const conn = new web3.Connection(RPC, "confirmed");
  // finalized: see the module comment.
  const blockhash = (await conn.getLatestBlockhash("finalized")).blockhash;
  const mk = (ixs) => {
    const tx = new web3.Transaction({ recentBlockhash: blockhash, feePayer: FUNDED });
    ixs.forEach((i) => tx.add(i));
    return tx;
  };

  const fixtures = [];
  const dest = web3.Keypair.generate().publicKey;
  const attacker = web3.Keypair.generate().publicKey;

  // 1. Ordinary SOL transfer. Declared effect: debit + credit.
  {
    const ix = web3.SystemProgram.transfer({ fromPubkey: FUNDED, toPubkey: dest, lamports: 1_000_000 });
    fixtures.push(fixture("sol_transfer", ix, mk([ix]), {
      text: "Send 0.001 SOL on devnet",
      expect: "L4 clean: the observed debit/credit matches the manifest",
    }));
  }

  // 2. Multi-instruction: two transfers in one transaction.
  {
    const a = web3.SystemProgram.transfer({ fromPubkey: FUNDED, toPubkey: dest, lamports: 2_000_000 });
    const b = web3.SystemProgram.transfer({ fromPubkey: FUNDED, toPubkey: attacker, lamports: 2_000_000 });
    fixtures.push(fixture("multi_instruction", a, mk([a, b]), {
      text: "Two SOL transfers in one devnet transaction",
      expect: "both instructions assessed; state diff covers both destinations",
      transaction_instructions: [a, b].map((i) => {
        const p = project(i);
        return {
          program_id: p.program_id,
          instruction_discriminator: p.instruction_discriminator,
          account_addresses: p.account_addresses,
          cpi_targets: [],
        };
      }),
    }));
  }

  // 3. THE KEY L4 CASE. Structurally an ordinary System-program call, sold as a
  //    transfer, whose real state effect is an OWNERSHIP CHANGE. Nothing static
  //    about the request says "takeover" - only the observed post-state does.
  {
    const ix = web3.SystemProgram.assign({ accountPubkey: FUNDED, programId: new web3.PublicKey(attacker) });
    fixtures.push(fixture("hidden_ownership_change", ix, mk([ix]), {
      intent: "transfer",
      text: "just a small transfer",
      expect: "L4 MUST flag UndeclaredOwnerReassignment from the observed post-state",
    }));
  }

  // 4. Account creation: a real state effect (new account, rent debited).
  {
    const newAcct = web3.Keypair.generate();
    const ix = web3.SystemProgram.createAccount({
      fromPubkey: FUNDED,
      newAccountPubkey: newAcct.publicKey,
      lamports: 2_500_000,
      space: 100,
      programId: web3.SystemProgram.programId,
    });
    fixtures.push(fixture("account_create", ix, mk([ix]), {
      intent: "create",
      text: "Create a devnet account",
      expect: "L4 sees creation + rent debit",
    }));
  }

  // 5. Allocate + assign: the alloc/assign takeover shape, declared as create.
  {
    const newAcct = web3.Keypair.generate();
    const create = web3.SystemProgram.createAccount({
      fromPubkey: FUNDED,
      newAccountPubkey: newAcct.publicKey,
      lamports: 2_500_000,
      space: 100,
      programId: new web3.PublicKey(attacker),
    });
    fixtures.push(fixture("create_owned_by_attacker", create, mk([create]), {
      intent: "create",
      text: "Create an account owned by another program",
      expect: "creation is declared, so the owner assignment is excused - contrast with #3",
    }));
  }

  // 6. Larger transfer: same shape, different magnitude (baseline sanity).
  {
    const ix = web3.SystemProgram.transfer({ fromPubkey: FUNDED, toPubkey: dest, lamports: 500_000_000 });
    fixtures.push(fixture("large_sol_transfer", ix, mk([ix]), {
      text: "Send 0.5 SOL on devnet",
      expect: "clean diff, larger magnitude",
    }));
  }

  // 7. THE CASE ONLY L4 CAN CATCH.
  //
  //    The PRIMARY instruction is an ordinary SOL transfer, and every static
  //    check agrees: the manifest matches, the discriminator is Transfer, the
  //    declared effects are debit + credit, the intent says transfer. Nothing
  //    in the request is suspicious.
  //
  //    A second instruction in the same transaction reassigns the payer's
  //    account to an attacker-controlled program. That effect appears ONLY in
  //    the observed post-state of an account the primary instruction writes —
  //    it is invisible to the manifest, to the discriminator, and to the
  //    intent. This is "statically safe, runtime malicious", and the state diff
  //    is the only layer positioned to see it.
  {
    const transfer = web3.SystemProgram.transfer({
      fromPubkey: FUNDED, toPubkey: dest, lamports: 1_000_000,
    });
    const takeover = web3.SystemProgram.assign({
      accountPubkey: FUNDED, programId: new web3.PublicKey(attacker),
    });
    fixtures.push(fixture("benign_primary_malicious_effect", transfer, mk([transfer, takeover]), {
      intent: "transfer",
      text: "Send 0.001 SOL to my friend",
      expect: "primary instruction is statically clean; ONLY the observed post-state shows the takeover",
      transaction_instructions: [transfer].map((i) => {
        const p = project(i);
        return {
          program_id: p.program_id,
          instruction_discriminator: p.instruction_discriminator,
          account_addresses: p.account_addresses,
          cpi_targets: [],
        };
      }),
    }));
  }

  fs.writeFileSync(path.join(OUT, "fixtures.json"), JSON.stringify(fixtures, null, 1));
  fs.writeFileSync(
    path.join(OUT, "meta.json"),
    JSON.stringify(
      {
        network: "devnet",
        rpc: RPC,
        fee_payer: FUNDED.toBase58(),
        note: "read-only simulation only; nothing signed, nothing submitted",
        blockhash_commitment: "finalized",
        built_at: new Date().toISOString(),
      },
      null,
      1
    )
  );

  // Prove each blob actually simulates before handing them to Graphite -
  // otherwise a Graphite "Inconclusive" would be the harness's fault.
  console.log("pre-flight: does each blob simulate cleanly against devnet?");
  for (const f of fixtures) {
    const b64 = Buffer.from(f.signed_transaction).toString("base64");
    const r = await fetch(RPC, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0", id: 1, method: "simulateTransaction",
        params: [b64, { encoding: "base64", accounts: { encoding: "base64", addresses: f.account_addresses.slice(0, 10) } }],
      }),
    });
    const v = (await r.json()).result?.value;
    console.log(
      `  ${f.__name.padEnd(26)} err=${JSON.stringify(v?.err)} units=${v?.unitsConsumed} post_accounts=${(v?.accounts || []).filter(Boolean).length}`
    );
  }
  console.log(`\nwrote ${fixtures.length} fixtures to ${OUT}`);
}

main().catch((e) => {
  console.error("fixture build failed:", e);
  process.exit(1);
});

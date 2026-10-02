/**
 * R-P8, phase 1: `@solana/kit` compiles the bridge's transactions to the SAME
 * bytes `@solana/web3.js` does.
 *
 * The Core's verdict is bound to bytes. Before kit may compile anything the
 * bridge submits, it has to be shown equivalent to the bridge's production
 * path (`BoundTransaction.build`, web3.js), and the comparison is as strict as
 * the two encodings allow:
 *
 *   - LEGACY: byte for byte. Both compilers sort the accounts within each
 *     privilege class, so they must produce identical bytes.
 *   - V0: the same transaction, not the same bytes. web3.js's
 *     `compileToV0Message` keeps accounts in order of first appearance within
 *     a class; kit sorts them, as both do for legacy. The messages therefore
 *     differ in byte order while saying the same thing. Equivalence is checked
 *     exactly: identical header, identical lookup tables and the same entries
 *     drawn from each, and every instruction resolving to the same program,
 *     the same accounts in the same order with the same signer and writable
 *     flags, and the same data. That is the whole meaning of a message.
 *
 * This does not loosen what Graphite binds: the bridge verifies, signs and
 * submits ONE byte string whichever compiler made it (the digest is checked
 * before signing). It does mean a v0 transaction compiled by kit is a
 * different byte string from the one web3.js would have made, so the
 * cross-language corpus is regenerated and the Rust Core re-verifies it.
 *
 * The cases are generated from a fixed seed: a pool of keys, signers among
 * them, programs, instruction data of varying length, lookup tables holding
 * some of the keys. Deterministic, so a failure reproduces.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  AddressLookupTableAccount,
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";
import bs58 from "bs58";
import { BoundTransaction } from "./artifact.js";
import { compileUnsignedWithKit } from "./kit-artifact.js";

/** A small deterministic generator (xorshift32). */
function rng(seed: number) {
  let s = seed >>> 0 || 1;
  const next = () => {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5;
    s >>>= 0;
    return s;
  };
  return {
    int: (n: number) => next() % n,
    bool: (p = 0.5) => next() / 0x100000000 < p,
    bytes: (n: number) => Uint8Array.from({ length: n }, () => next() & 0xff),
  };
}

const PROGRAMS = [
  SystemProgram.programId,
  new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
  new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"),
  new PublicKey("ComputeBudget111111111111111111111111111111"),
];

interface Case {
  instructions: TransactionInstruction[];
  feePayer: PublicKey;
  recentBlockhash: string;
  lastValidBlockHeight: number;
  tables: AddressLookupTableAccount[];
}

function generate(seed: number, withTables: boolean): Case {
  const r = rng(seed);
  const pool = Array.from({ length: 6 + r.int(14) }, () => Keypair.fromSeed(r.bytes(32)).publicKey);
  const feePayer = pool[0];
  // At most two signers besides the fee payer, as real transactions have.
  const signers = new Set([feePayer.toBase58()]);
  for (let i = 1; i < pool.length && signers.size < 3; i++) if (r.bool(0.15)) signers.add(pool[i].toBase58());
  const programs = [...PROGRAMS, ...Array.from({ length: 3 }, () => Keypair.fromSeed(r.bytes(32)).publicKey)];
  const instructions = Array.from({ length: 1 + r.int(6) }, () => {
    const keys = Array.from({ length: r.int(9) }, () => {
      const pubkey = pool[r.int(pool.length)];
      return { pubkey, isSigner: signers.has(pubkey.toBase58()) && r.bool(0.7), isWritable: r.bool(0.5) };
    });
    return new TransactionInstruction({
      programId: programs[r.int(programs.length)],
      keys,
      data: Buffer.from(r.bytes(r.int(48))),
    });
  });
  const tables = withTables
    ? Array.from({ length: 1 + r.int(2) }, () => {
        const addresses = pool.filter((k) => !signers.has(k.toBase58()) && r.bool(0.6));
        return new AddressLookupTableAccount({
          key: Keypair.fromSeed(r.bytes(32)).publicKey,
          state: {
            deactivationSlot: BigInt("18446744073709551615"),
            lastExtendedSlot: 0,
            lastExtendedSlotStartIndex: 0,
            authority: undefined,
            addresses,
          },
        });
      })
    : [];
  return {
    instructions,
    feePayer,
    recentBlockhash: bs58.encode(r.bytes(32)),
    lastValidBlockHeight: 1000 + r.int(100000),
    tables,
  };
}

function hex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

function readShortU16(b: Uint8Array, i: number): [number, number] {
  let v = 0;
  for (let g = 0; g < 3; g++) {
    const x = b[i++];
    v |= (x & 0x7f) << (7 * g);
    if (!(x & 0x80)) break;
  }
  return [v, i];
}

/**
 * What a legacy or v0 message MEANS: header, lookups, and every instruction
 * resolved to addresses with their runtime privileges. Lookup-table entries
 * resolve through the tables the test built.
 */
function meaning(raw: Uint8Array, tables: AddressLookupTableAccount[]) {
  let [n, i] = readShortU16(raw, 0);
  i += 64 * n;
  const v0 = (raw[i] & 0x80) !== 0;
  if (v0) i++;
  const header = [raw[i], raw[i + 1], raw[i + 2]];
  i += 3;
  let nk: number;
  [nk, i] = readShortU16(raw, i);
  const keys: string[] = [];
  for (let k = 0; k < nk; k++, i += 32) keys.push(bs58.encode(raw.subarray(i, i + 32)));
  const blockhash = bs58.encode(raw.subarray(i, i + 32));
  i += 32;
  let nix: number;
  [nix, i] = readShortU16(raw, i);
  const ixs: { program: number; accounts: number[]; data: string }[] = [];
  for (let x = 0; x < nix; x++) {
    const program = raw[i++];
    let na: number;
    [na, i] = readShortU16(raw, i);
    const accounts = Array.from(raw.subarray(i, i + na));
    i += na;
    let nd: number;
    [nd, i] = readShortU16(raw, i);
    ixs.push({ program, accounts, data: hex(raw.subarray(i, i + nd)) });
    i += nd;
  }
  const loadedW: string[] = [];
  const loadedR: string[] = [];
  const lookups: { table: string; writable: string[]; readonly: string[] }[] = [];
  if (v0) {
    let nl: number;
    [nl, i] = readShortU16(raw, i);
    for (let l = 0; l < nl; l++) {
      const table = bs58.encode(raw.subarray(i, i + 32));
      i += 32;
      const entries = tables.find((t) => t.key.toBase58() === table)!.state.addresses.map((a) => a.toBase58());
      let nw: number;
      [nw, i] = readShortU16(raw, i);
      const w = Array.from(raw.subarray(i, i + nw)).map((x) => entries[x]);
      i += nw;
      let nr: number;
      [nr, i] = readShortU16(raw, i);
      const r = Array.from(raw.subarray(i, i + nr)).map((x) => entries[x]);
      i += nr;
      loadedW.push(...w);
      loadedR.push(...r);
      lookups.push({ table, writable: [...w].sort(), readonly: [...r].sort() });
    }
  }
  assert.equal(i, raw.length, "the decoder consumed the whole frame");
  const all = [...keys, ...loadedW, ...loadedR];
  const [sigs, roSigned, roUnsigned] = header;
  const privilege = (x: number) => {
    const signer = x < sigs;
    const writable =
      x < keys.length
        ? signer
          ? x < sigs - roSigned
          : x < keys.length - roUnsigned
        : x < keys.length + loadedW.length;
    return `${all[x]}:${signer ? "S" : ""}${writable ? "W" : ""}`;
  };
  return {
    v0,
    header: header.join(","),
    blockhash,
    lookups: lookups.sort((a, b) => a.table.localeCompare(b.table)),
    instructions: ixs.map((ix) => ({
      program: all[ix.program],
      accounts: ix.accounts.map(privilege),
      data: ix.data,
    })),
  };
}

/** Compare the two compilers on `count` seeded cases of one shape. */
function differential(label: string, version: "legacy" | 0, withTables: boolean, count: number) {
  let compared = 0;
  let skipped = 0;
  for (let seed = 1; seed <= count; seed++) {
    const c = generate(seed * 7919 + (withTables ? 13 : 0) + (version === 0 ? 1 : 0), withTables);
    let web3: Uint8Array;
    try {
      web3 = BoundTransaction.build({
        instructions: c.instructions,
        feePayer: c.feePayer,
        recentBlockhash: c.recentBlockhash,
        lastValidBlockHeight: c.lastValidBlockHeight,
        version,
        addressLookupTables: c.tables,
      }).artifactBytes;
    } catch {
      // The production path refuses this case (too large, durable nonce):
      // nothing it would submit to compare.
      skipped++;
      continue;
    }
    const kit = compileUnsignedWithKit({
      instructions: c.instructions,
      feePayer: c.feePayer,
      recentBlockhash: c.recentBlockhash,
      lastValidBlockHeight: c.lastValidBlockHeight,
      version,
      addressLookupTables: c.tables,
    });
    if (version === "legacy") {
      assert.equal(hex(kit), hex(web3), `${label}: seed ${seed} compiles to different bytes`);
    } else {
      assert.deepEqual(
        meaning(kit, c.tables),
        meaning(web3, c.tables),
        `${label}: seed ${seed} compiles to a different transaction`,
      );
      assert.equal(kit.length, web3.length, `${label}: seed ${seed} differs in length`);
    }
    compared++;
  }
  assert.ok(compared > count / 2, `${label}: only ${compared} of ${count} cases were comparable (${skipped} refused)`);
  return compared;
}

test("R-P8 phase 1: kit compiles legacy messages to web3.js's bytes", () => {
  differential("legacy", "legacy", false, 500);
});

test("R-P8 phase 1: kit compiles v0 messages without lookup tables to the same transaction as web3.js", () => {
  differential("v0", 0, false, 500);
});

test("R-P8 phase 1: kit compiles v0 messages reading lookup tables to the same transaction as web3.js", () => {
  differential("v0+ALT", 0, true, 500);
});

test("R-P8 phase 1: the v0 comparison is not vacuous — a changed flag or data byte is a different transaction", () => {
  // Privileges are per MESSAGE: an account is writable if any instruction
  // marks it so. The flip must therefore hit an account that occurs once in
  // the whole transaction, or it would rightly change nothing.
  let c = generate(4242, true);
  const occurrences = (cc: Case) => {
    const count = new Map<string, number>();
    for (const ix of cc.instructions) {
      count.set(ix.programId.toBase58(), (count.get(ix.programId.toBase58()) ?? 0) + 1);
      for (const k of ix.keys) count.set(k.pubkey.toBase58(), (count.get(k.pubkey.toBase58()) ?? 0) + 1);
    }
    count.set(cc.feePayer.toBase58(), (count.get(cc.feePayer.toBase58()) ?? 0) + 1);
    return count;
  };
  let seed = 4242;
  const findTarget = (cc: Case) => {
    const once = occurrences(cc);
    for (let n = 0; n < cc.instructions.length; n++) {
      const j = cc.instructions[n].keys.findIndex((k) => !k.isSigner && once.get(k.pubkey.toBase58()) === 1);
      if (j >= 0) return [n, j] as const;
    }
    return null;
  };
  let target = findTarget(c);
  while (!target) {
    c = generate(++seed, true);
    target = findTarget(c);
  }
  const [n, j] = target;
  const build = (instructions: TransactionInstruction[]) =>
    compileUnsignedWithKit({
      instructions,
      feePayer: c.feePayer,
      recentBlockhash: c.recentBlockhash,
      lastValidBlockHeight: c.lastValidBlockHeight,
      version: 0,
      addressLookupTables: c.tables,
    });
  const original = meaning(build(c.instructions), c.tables);
  const withFlag = c.instructions.map((ix, x) =>
    x !== n
      ? ix
      : new TransactionInstruction({
          programId: ix.programId,
          data: ix.data,
          keys: ix.keys.map((k, y) => (y === j ? { ...k, isWritable: !k.isWritable } : k)),
        }),
  );
  assert.notDeepEqual(meaning(build(withFlag), c.tables), original, "a flipped writable flag");
  const withData = c.instructions.map((ix, x) =>
    x !== 0
      ? ix
      : new TransactionInstruction({
          programId: ix.programId,
          keys: ix.keys,
          data: Buffer.concat([ix.data, Buffer.from([0x5a])]),
        }),
  );
  assert.notDeepEqual(meaning(build(withData), c.tables), original, "an extra data byte");
});

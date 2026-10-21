/**
 * What an approved, artifact-bound verdict may still not have observed — and
 * which of those residuals this deployment has decided to accept.
 *
 * Every artifact-bound verdict carries `scope.unobserved`: the
 * security-relevant properties Graphite did not independently establish. Until
 * Round 9 (2026-09-12) that list was prose, and the bridge printed it and
 * executed anyway. "Surfaced, not gated" was the documented position, and it
 * left the actual decision to whoever read the log. A gate that reports a
 * residual and then signs has not gated on it.
 *
 * The core now names each residual with a stable code (`unobserved_codes[i]`
 * names `unobserved[i]`). Two of them are inherent to every artifact-bound
 * verdict — what programs without manifests DO beyond their simulated effects,
 * and CPI callees that only simulation can see — and a policy that accepts only
 * those accepts nothing the pipeline could have observed and did not. Every
 * other code names an observation that was possible and did not happen: no
 * simulation, no state diff, privileges taken from the caller, lookup tables
 * unresolved, an artifact that did not parse, an instruction that was not
 * located. None of those is acceptable by default. An operator who wants to
 * execute under one of them says so, by code, in configuration — never by
 * reading a warning and proceeding.
 *
 * Constitution: P1 (the policy is configuration, not a model's judgement), P2
 * (deterministic over the codes), P3 (every refusal names the code and the
 * prose behind it), P12 (an unknown code, a missing list, or a server that does
 * not report codes is a refusal), P14 (the accepted set is recorded on the
 * execution outcome).
 */

import {
  INHERENT_UNOBSERVED,
  UNOBSERVED_CODES,
  type UnobservedCode,
  type VerificationScope,
} from "../../sdk/typescript/src/types.js";

/** Environment variable naming the residual codes a deployment accepts. */
export const ACCEPT_UNOBSERVED_ENV = "GRAPHITE_ACCEPT_UNOBSERVED";

const KNOWN: ReadonlySet<string> = new Set<string>(UNOBSERVED_CODES);

/**
 * The Core's execution decision (Round 30, G-01): `decision` on a verdict,
 * with `executable` true exactly when it is `executable_approved`. Only that
 * value permits signing; `approved` alone never did. Any other string is a
 * decision this guard does not know, and is not executable.
 */
export const EXECUTION_DECISIONS = ["executable_approved", "analysis_only", "inconclusive", "blocked"] as const;
export type ExecutionDecision = (typeof EXECUTION_DECISIONS)[number];

/** What the policy established about one verdict it allowed through. */
export interface ResidualDecision {
  /** Non-inherent residuals that were present and accepted by configuration. */
  accepted: UnobservedCode[];
  /** Inherent residuals present (always allowed; recorded for completeness). */
  inherent: UnobservedCode[];
  /**
   * The execution decision recomputed here from the verdict's scope:
   * `executable_approved` when nothing beyond the inherent residuals is
   * unobserved, `analysis_only` when the deployment accepted the rest by name.
   */
  decision: "executable_approved" | "analysis_only";
  /** What the Core reported as `decision`, or null for a server that predates it. */
  reportedDecision: ExecutionDecision | null;
}

/** The parts of a verdict the execution decision is read from. */
export interface DecidableVerdict {
  approved: boolean;
  scope?: VerificationScope;
  decision?: unknown;
  executable?: unknown;
}

/**
 * The residual policy refused an approved verdict: Graphite did not observe
 * something this deployment has not accepted, or the verdict is not bound to
 * the bytes. A refusal, not an error — a tool reports it as such.
 */
export class ResidualPolicyRefusal extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ResidualPolicyRefusal";
  }
}

export class ResidualPolicy {
  // An ES private field (Round 30): a TypeScript `private` Set was reachable
  // at runtime as `policy.acceptedCodes` and could be `.add`ed to.
  readonly #acceptedCodes: ReadonlySet<UnobservedCode>;

  /**
   * @param accepted The non-inherent codes this deployment accepts. Each must
   * be a real code: a typo would otherwise silently accept nothing — which is
   * safe — or, worse, be read by an operator as accepting something. Inherent
   * codes may be listed; they are allowed regardless.
   */
  constructor(accepted: readonly string[] = []) {
    const set = new Set<UnobservedCode>();
    for (const raw of accepted) {
      const code = raw.trim();
      if (code.length === 0) continue;
      if (!KNOWN.has(code)) {
        throw new Error(
          `[Graphite] ResidualPolicy: "${code}" is not an unobserved code. Known codes: ${UNOBSERVED_CODES.join(", ")}.`,
        );
      }
      set.add(code as UnobservedCode);
    }
    this.#acceptedCodes = set;
    Object.freeze(this);
  }

  /**
   * The policy named by `GRAPHITE_ACCEPT_UNOBSERVED` (comma-separated codes),
   * or the default — inherent residuals only — when it is unset.
   */
  static fromEnv(env: NodeJS.ProcessEnv = process.env): ResidualPolicy {
    const raw = env[ACCEPT_UNOBSERVED_ENV];
    if (!raw) return new ResidualPolicy();
    return new ResidualPolicy(raw.split(","));
  }

  /** The non-inherent codes this policy accepts, sorted, for logs and outcomes. */
  accepts(): UnobservedCode[] {
    return [...this.#acceptedCodes].filter((c) => !INHERENT_UNOBSERVED.has(c)).sort();
  }

  /**
   * Refuse unless every residual on this verdict is inherent or accepted.
   *
   * Requires an artifact-bound scope that reports codes. A descriptive scope
   * has nothing to execute; a scope without `unobserved_codes` came from a
   * server that predates them, and "no codes" is not "nothing unobserved" —
   * the prose on the same verdict says otherwise. Codes and prose are paired
   * by position, so a length mismatch is a malformed verdict and a refusal.
   */
  assertExecutable(scope: VerificationScope | undefined, label: string): Omit<ResidualDecision, "decision" | "reportedDecision"> {
    if (scope?.kind !== "artifact_bound") {
      throw new ResidualPolicyRefusal(
        `[Graphite] ${label}: the verdict is ${scope?.kind ?? "unscoped"}, not artifact_bound. ` +
          "A descriptive verdict describes what the request SAID; it does not constrain what " +
          "gets signed. ABORTING.",
      );
    }
    const codes = scope.unobserved_codes;
    if (!codes) {
      throw new ResidualPolicyRefusal(
        `[Graphite] ${label}: this Graphite server reports what it did not observe as prose only ` +
          "(no scope.unobserved_codes; pre-2026-09-12). The residual policy cannot decide on prose, " +
          "and refuses rather than execute on an undecided verdict. Upgrade the server. ABORTING.",
      );
    }
    if (codes.length !== scope.unobserved.length) {
      throw new ResidualPolicyRefusal(
        `[Graphite] ${label}: malformed verdict — ${codes.length} unobserved code(s) for ` +
          `${scope.unobserved.length} unobserved entr(ies). ABORTING.`,
      );
    }
    const inherent: UnobservedCode[] = [];
    const accepted: UnobservedCode[] = [];
    const refused: string[] = [];
    codes.forEach((code, i) => {
      if (!KNOWN.has(code)) {
        // A code this bridge does not know is a residual it cannot have
        // accepted. Newer server, older bridge: refuse, and say which.
        refused.push(`${code} (unknown to this bridge): ${scope.unobserved[i]}`);
      } else if (INHERENT_UNOBSERVED.has(code)) {
        inherent.push(code);
      } else if (this.#acceptedCodes.has(code)) {
        accepted.push(code);
      } else {
        refused.push(`${code}: ${scope.unobserved[i]}`);
      }
    });
    if (refused.length > 0) {
      throw new ResidualPolicyRefusal(
        [
          `[Graphite] ${label}: the verdict is approved and artifact-bound, but Graphite did not observe ` +
            `${refused.length} propert(ies) this deployment has not accepted:`,
          ...refused.map((r) => `  - ${r}`),
          `To execute under a residual, name its code in ${ACCEPT_UNOBSERVED_ENV} (comma-separated) ` +
            "or in VerifiedSakAgent.create({ acceptUnobserved: [...] }). ABORTING.",
        ].join("\n"),
      );
    }
    return { accepted, inherent };
  }

  /**
   * The whole execution decision on one verdict (Round 30, G-01): approved,
   * artifact-bound, every residual inherent or accepted — and, when the Core
   * reports its own `decision`, the same answer.
   *
   * The Core's `decision` is not taken on trust: it is recomputed here from
   * the scope, and a server that says `executable_approved` over a residual,
   * or `analysis_only` over none, or `blocked` on an approval, or a value
   * this guard does not know, disagrees with its own verdict and is refused.
   * `executable` must say the same as `decision`. A server that reports no
   * `decision` (one that predates it) is judged by the recomputation alone,
   * which is what this policy always did.
   *
   * `analysis_only` proceeds only when every residual that made it so is one
   * the operator accepted by name; nothing else turns it into a signature.
   */
  assertExecutableVerdict(verdict: DecidableVerdict, label: string): ResidualDecision {
    if (verdict.approved !== true) {
      throw new ResidualPolicyRefusal(`[Graphite] ${label}: the verdict is not an approval. ABORTING.`);
    }
    const reported = verdict.decision;
    if (reported !== undefined && !(EXECUTION_DECISIONS as readonly unknown[]).includes(reported)) {
      throw new ResidualPolicyRefusal(
        `[Graphite] ${label}: the verdict's decision ${JSON.stringify(reported)} is not one this guard knows ` +
          `(${EXECUTION_DECISIONS.join(", ")}). An unknown decision is not an executable one. ABORTING.`,
      );
    }
    if (verdict.executable !== undefined && typeof verdict.executable !== "boolean") {
      throw new ResidualPolicyRefusal(`[Graphite] ${label}: the verdict's \`executable\` is not a boolean. ABORTING.`);
    }
    if (reported === "blocked" || reported === "inconclusive") {
      throw new ResidualPolicyRefusal(
        `[Graphite] ${label}: the verdict says approved but its decision is "${reported}". A verdict that ` +
          "contradicts itself is not executed. ABORTING.",
      );
    }
    const { accepted, inherent } = this.assertExecutable(verdict.scope, label);
    const decision = accepted.length === 0 ? "executable_approved" : "analysis_only";
    if (reported !== undefined && reported !== decision) {
      throw new ResidualPolicyRefusal(
        `[Graphite] ${label}: the Core decided "${reported}", but its own scope makes this verdict ` +
          `"${decision}" (${accepted.length === 0 ? "nothing beyond the inherent residuals is unobserved" : `unobserved: ${accepted.join(", ")}`}). ` +
          "The two must agree before anything is signed. ABORTING.",
      );
    }
    const effective = (reported as ExecutionDecision | undefined) ?? decision;
    if (verdict.executable !== undefined && verdict.executable !== (effective === "executable_approved")) {
      throw new ResidualPolicyRefusal(
        `[Graphite] ${label}: the verdict's \`executable\` (${String(verdict.executable)}) contradicts its ` +
          `decision "${effective}". ABORTING.`,
      );
    }
    return { accepted, inherent, decision, reportedDecision: (reported as ExecutionDecision | undefined) ?? null };
  }
}
// Round 30: the gate's methods cannot be replaced at runtime by code holding
// the class (an in-process tool or plugin): `ResidualPolicy.prototype.
// assertExecutableVerdict = () => ...` throws instead of switching it off.
Object.freeze(ResidualPolicy.prototype);
Object.freeze(ResidualPolicy);

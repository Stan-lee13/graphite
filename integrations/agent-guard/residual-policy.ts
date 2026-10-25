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
  computeExecutionDecision,
  INHERENT_UNOBSERVED,
  isArtifactBound,
  UNOBSERVED_CODES,
  type DecisionInputs,
  type UnobservedCode,
  type VerificationScope,
} from "../../sdk/typescript/src/types.js";

/** Environment variable naming the residual codes a deployment accepts. */
export const ACCEPT_UNOBSERVED_ENV = "GRAPHITE_ACCEPT_UNOBSERVED";

const KNOWN: ReadonlySet<string> = new Set<string>(UNOBSERVED_CODES);

/**
 * Codes no deployment may accept (Round 38, G2-5). `intent_parameters` says
 * the Core could not tie the request's amount, recipient or asset to the
 * bytes (Round 36, F-003). Accepting it signs whatever the bytes do whatever
 * the request said: it switches F-003 off for the whole deployment, for
 * every request, not one residual about one property of a program. Naming it
 * in GRAPHITE_ACCEPT_UNOBSERVED or `acceptUnobserved` refuses to start.
 */
export const NEVER_ACCEPTABLE: ReadonlySet<UnobservedCode> = new Set<UnobservedCode>(["intent_parameters"]);

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
  /**
   * What the Core reported as `decision`. Always present since Round 34: a
   * response without one is refused. (Typed nullable for callers that
   * recorded outcomes before.)
   */
  reportedDecision: ExecutionDecision | null;
}

/** The parts of a verdict the execution decision is read from. */
export interface DecidableVerdict {
  approved: boolean;
  scope?: VerificationScope;
  decision?: unknown;
  executable?: unknown;
  /** Round 34 (G-5): the rest of the Core's rule. Missing is never executable. */
  risk_verdict?: Partial<DecisionInputs["risk_verdict"]>;
  policy_verdict?: unknown;
  layers?: DecisionInputs["layers"];
}

/** Residuals that, accepted, explain a scope with `simulated: false`. */
const EXPLAINS_NO_SIMULATION: ReadonlySet<UnobservedCode> = new Set<UnobservedCode>(["not_simulated", "simulation_failed"]);

/**
 * Why the Core's execution rule (`computeExecutionDecision`) does not call
 * `v` executable, beyond its unobserved codes — which the caller has already
 * judged. Empty when it does.
 */
function unmetConditions(v: DecidableVerdict): string[] {
  const why: string[] = [];
  const risk = v.risk_verdict?.status;
  if (risk !== "Clear") why.push(`risk is ${JSON.stringify(risk ?? "absent")}, not Clear`);
  if (v.policy_verdict !== "Approved") why.push(`policy verdict is ${JSON.stringify(v.policy_verdict ?? "absent")}, not Approved`);
  if (!isArtifactBound({ scope: v.scope })) why.push("no transaction digest the verdict is bound to");
  if (v.scope?.kind === "artifact_bound" && v.scope.simulated !== true) why.push("the transaction was not simulated");
  if (!Array.isArray(v.layers)) {
    why.push("no layers reported");
  } else {
    for (const l of v.layers) if (l.status === "failed") why.push(`layer ${l.layer} failed`);
  }
  return why;
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
      if (NEVER_ACCEPTABLE.has(code as UnobservedCode)) {
        throw new Error(
          `[Graphite] ResidualPolicy: "${code}" cannot be accepted: it means the Core could not tie the request's ` +
            "amount, recipient or asset to the transaction (F-003), and accepting it would sign whatever the bytes do " +
            `for every request. Remove it from ${ACCEPT_UNOBSERVED_ENV} / acceptUnobserved. REFUSING TO START.`,
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
      } else if (NEVER_ACCEPTABLE.has(code)) {
        refused.push(`${code} (never acceptable): ${scope.unobserved[i]}`);
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
            "or in VerifiedSakAgent.create({ acceptUnobserved: [...] }); a code marked never acceptable cannot " +
            "be named (Round 38): the request must be one the Core can bind. ABORTING.",
        ].join("\n"),
      );
    }
    return { accepted, inherent };
  }

  /**
   * The whole execution decision on one verdict (Round 30, G-01; Round 34,
   * G-5): approved, every residual inherent or accepted, the Core's
   * `decision` reported and the same answer, and the rest of the Core's
   * rule recomputed here — risk Clear, policy Approved, an artifact-bound
   * scope with its digest that was simulated, layers reported and none
   * failed — through the SDK's `computeExecutionDecision`.
   *
   * The Core's `decision` is not taken on trust, and it is not optional: a
   * response without `decision` and a boolean `executable` (a server older
   * than Round 30) is refused, not judged by the codes alone. A server that
   * says `executable_approved` over a residual, a non-Clear risk, a policy
   * refusal, a missing simulation or a failed layer, or `analysis_only` over
   * none, or `blocked` on an approval, or a value this guard does not know,
   * disagrees with its own verdict and is refused.
   *
   * `analysis_only` proceeds only when every residual that made it so is one
   * the operator accepted by name, and everything else the rule requires
   * holds: an accepted residual excuses itself, nothing more. (An accepted
   * `not_simulated` or `simulation_failed` is what excuses `simulated:
   * false`.) Nothing else turns an analysis into a signature.
   */
  assertExecutableVerdict(verdict: DecidableVerdict, label: string): ResidualDecision {
    if (verdict.approved !== true) {
      throw new ResidualPolicyRefusal(`[Graphite] ${label}: the verdict is not an approval. ABORTING.`);
    }
    const reported = verdict.decision;
    if (reported === undefined) {
      throw new ResidualPolicyRefusal(
        `[Graphite] ${label}: the verdict has no \`decision\` field (a Core older than Round 30). The guard signs ` +
          "only on the Core's own executable decision, recomputed and agreed; it does not stand in for a decision " +
          "the server did not make. Upgrade the Core. ABORTING.",
      );
    }
    if (!(EXECUTION_DECISIONS as readonly unknown[]).includes(reported)) {
      throw new ResidualPolicyRefusal(
        `[Graphite] ${label}: the verdict's decision ${JSON.stringify(reported)} is not one this guard knows ` +
          `(${EXECUTION_DECISIONS.join(", ")}). An unknown decision is not an executable one. ABORTING.`,
      );
    }
    if (reported === "blocked" || reported === "inconclusive") {
      throw new ResidualPolicyRefusal(
        `[Graphite] ${label}: the verdict says approved but its decision is "${reported}". A verdict that ` +
          "contradicts itself is not executed. ABORTING.",
      );
    }
    if (typeof verdict.executable !== "boolean") {
      throw new ResidualPolicyRefusal(`[Graphite] ${label}: the verdict's \`executable\` is not a boolean. ABORTING.`);
    }
    const { accepted, inherent } = this.assertExecutable(verdict.scope, label);
    const decision = accepted.length === 0 ? "executable_approved" : "analysis_only";
    if (reported !== decision) {
      throw new ResidualPolicyRefusal(
        `[Graphite] ${label}: the Core decided "${reported}", but its own scope makes this verdict ` +
          `"${decision}" (${accepted.length === 0 ? "nothing beyond the inherent residuals is unobserved" : `unobserved: ${accepted.join(", ")}`}). ` +
          "The two must agree before anything is signed. ABORTING.",
      );
    }
    if (verdict.executable !== (decision === "executable_approved")) {
      throw new ResidualPolicyRefusal(
        `[Graphite] ${label}: the verdict's \`executable\` (${String(verdict.executable)}) contradicts its ` +
          `decision "${decision}". ABORTING.`,
      );
    }
    // Round 34 (G-5): the rest of the Core's rule. For an accepted residual,
    // the rule is applied to the verdict without the residuals the operator
    // accepted by name (and, when one of them is the missing simulation,
    // without that too): what they explain is excused, nothing else.
    const scope = verdict.scope as Extract<VerificationScope, { kind: "artifact_bound" }>;
    const excused = new Set<UnobservedCode>(accepted);
    const codes = scope.unobserved_codes ?? [];
    const judged: DecidableVerdict =
      accepted.length === 0
        ? verdict
        : {
            ...verdict,
            scope: {
              ...scope,
              simulated: scope.simulated === true || accepted.some((c) => EXPLAINS_NO_SIMULATION.has(c)),
              unobserved: scope.unobserved.filter((_, i) => !excused.has(codes[i])),
              unobserved_codes: codes.filter((c) => !excused.has(c)),
            },
          };
    const unmet = unmetConditions(judged);
    if (unmet.length > 0 || computeExecutionDecision(judged as DecisionInputs) !== "executable_approved") {
      throw new ResidualPolicyRefusal(
        `[Graphite] ${label}: the Core decided "${reported}", but the verdict does not meet its own execution rule` +
          (accepted.length > 0 ? ` (with ${accepted.join(", ")} accepted)` : "") +
          `: ${unmet.length > 0 ? unmet.join("; ") : "the recomputed decision is not executable"}. ABORTING.`,
      );
    }
    return { accepted, inherent, decision, reportedDecision: reported as ExecutionDecision };
  }
}
// Round 30: the gate's methods cannot be replaced at runtime by code holding
// the class (an in-process tool or plugin): `ResidualPolicy.prototype.
// assertExecutableVerdict = () => ...` throws instead of switching it off.
Object.freeze(ResidualPolicy.prototype);
Object.freeze(ResidualPolicy);

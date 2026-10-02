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

/** What the policy established about one verdict it allowed through. */
export interface ResidualDecision {
  /** Non-inherent residuals that were present and accepted by configuration. */
  accepted: UnobservedCode[];
  /** Inherent residuals present (always allowed; recorded for completeness). */
  inherent: UnobservedCode[];
}

export class ResidualPolicy {
  private readonly acceptedCodes: ReadonlySet<UnobservedCode>;

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
    this.acceptedCodes = set;
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
    return [...this.acceptedCodes].filter((c) => !INHERENT_UNOBSERVED.has(c)).sort();
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
  assertExecutable(scope: VerificationScope | undefined, label: string): ResidualDecision {
    if (scope?.kind !== "artifact_bound") {
      throw new Error(
        `[Graphite] ${label}: the verdict is ${scope?.kind ?? "unscoped"}, not artifact_bound. ` +
          "A descriptive verdict describes what the request SAID; it does not constrain what " +
          "gets signed. ABORTING.",
      );
    }
    const codes = scope.unobserved_codes;
    if (!codes) {
      throw new Error(
        `[Graphite] ${label}: this Graphite server reports what it did not observe as prose only ` +
          "(no scope.unobserved_codes; pre-2026-09-12). The residual policy cannot decide on prose, " +
          "and refuses rather than execute on an undecided verdict. Upgrade the server. ABORTING.",
      );
    }
    if (codes.length !== scope.unobserved.length) {
      throw new Error(
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
      } else if (this.acceptedCodes.has(code)) {
        accepted.push(code);
      } else {
        refused.push(`${code}: ${scope.unobserved[i]}`);
      }
    });
    if (refused.length > 0) {
      throw new Error(
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
}

// The numbers the console derives from the trail, kept apart from the views
// so they can be tested under Node (figures.test.ts, `tsx --test`). Only
// type imports, which are erased.
//
// Round 29 (audit 2026-10-20, D1): `/api/confidence-history` returns the
// newest 500 verdicts and `/api/policy-violations` the newest 200 refusals
// (and 200 rejected requests), each with a `count` the server computes over
// the whole trail. The Overview printed `series.length` as "verifications on
// record", split Approved/Refused from the 500, and the Blocked view and the
// sidebar badge counted the 200 — so on any busy Core they stopped at 500 and
// 200 and disagreed with the Verifications view, which used `count`. Totals
// now come from the server's totals; a figure derived from the window says
// which window ("last 500").
//
// Round 29 (D4): an approval with no `transaction_sha256` is descriptive — it
// judged what the request said, not bytes anyone will sign (W22). It used to
// be counted and coloured as a green "Approved" everywhere but one table
// cell. It is now its own kind, counted and drawn apart.

//
// Round 30 (shared execution contract): an approval bound to bytes is still
// not permission to sign. Only a verdict the Core reports as
// `decision: "executable_approved"` with `executable: true` is; one judged
// without a simulation, with an unobserved residual outside the inherent
// set, or by a Core that does not report the decision at all, is an
// approval for analysis. The console drew every bound approval green
// "approved" — including the ones a Core with no RPC made, which no
// consumer may sign on. Green now means executable and nothing else; every
// other approval is amber and says which kind it is. An unknown decision
// string, or a decision and `executable` that disagree, is drawn as not
// executable: the fail-closed reading.

import type { ConfidenceHistory, ConfidencePoint, PolicyViolations } from "./api";

export type VerdictKind =
  /** decision "executable_approved", executable true, bound to bytes. */
  | "executable"
  /** Approved and bound, but the Core says it is not executable (or says
   *  something this console does not recognise). */
  | "analysis"
  /** Approved and bound, from a Core that does not report the decision. */
  | "unreported"
  /** Approved as described: no bytes at all (W22). */
  | "descriptive"
  /** Refused because required evidence could not be obtained. */
  | "inconclusive"
  | "refused";

export function verdictKind(
  p: Pick<ConfidencePoint, "approved" | "transaction_sha256" | "decision" | "executable">,
): VerdictKind {
  if (!p.approved) return p.decision === "inconclusive" ? "inconclusive" : "refused";
  if (!p.transaction_sha256) return "descriptive";
  if (p.decision === undefined || p.decision === null) return "unreported";
  return p.decision === "executable_approved" && p.executable === true ? "executable" : "analysis";
}

/** CSS tone for a verdict kind. Green is spent on executable approvals only. */
export function verdictTone(kind: VerdictKind): "pass" | "warn" | "block" {
  return kind === "executable" ? "pass" : kind === "refused" ? "block" : "warn";
}

export function verdictLabel(kind: VerdictKind): string {
  switch (kind) {
    case "executable":
      return "executable";
    case "analysis":
      return "approved · analysis only";
    case "unreported":
      return "approved · executability not reported";
    case "descriptive":
      return "approved · descriptive";
    case "inconclusive":
      return "inconclusive";
    case "refused":
      return "refused";
  }
}

/** One sentence on what the kind means, for titles and the legend. */
export function verdictMeaning(kind: VerdictKind): string {
  switch (kind) {
    case "executable":
      return "approved, bound to these transaction bytes, and reported executable: the only verdict a signer may act on";
    case "analysis":
      return "approved for analysis only: the Core reports it is not executable (no simulation, or an unobserved residual)";
    case "unreported":
      return "approved and bound to bytes, but this Core does not report whether it is executable; treat it as not executable";
    case "descriptive":
      return "approved as described, not bound to transaction bytes; constrains nothing that is signed";
    case "inconclusive":
      return "refused because required evidence could not be obtained";
    case "refused":
      return "refused";
  }
}

export interface WindowCounts {
  /** Points in the window the server returned. */
  n: number;
  executable: number;
  /** Approved, but not executable: analysis, unreported and descriptive. */
  notExecutable: number;
  descriptive: number;
  refused: number;
  inconclusive: number;
}

export function countWindow(series: readonly ConfidencePoint[]): WindowCounts {
  const c: WindowCounts = { n: series.length, executable: 0, notExecutable: 0, descriptive: 0, refused: 0, inconclusive: 0 };
  for (const p of series) {
    const k = verdictKind(p);
    if (k === "executable") c.executable++;
    else if (k === "refused") c.refused++;
    else if (k === "inconclusive") c.inconclusive++;
    else {
      c.notExecutable++;
      if (k === "descriptive") c.descriptive++;
    }
  }
  return c;
}

/** "last 500" when the window is shorter than the trail, "all 37" otherwise. */
export function windowLabel(n: number, total: number): string {
  return n < total ? `last ${n.toLocaleString()}` : `all ${n.toLocaleString()}`;
}

/** The server's per-list caps (server.rs CONFIDENCE_SERIES_CAP, VIOLATIONS_CAP). */
export const ERROR_VIOLATIONS_CAP = 200;

export interface RefusalTotals {
  /** Every refused verification on the trail. */
  refused: number;
  /** Rejected (unparseable) requests; a lower bound when `rejectedAtLeast`. */
  rejected: number;
  rejectedAtLeast: boolean;
}

/**
 * Whole-trail refusal totals. The server's `count` is the exact number of
 * refused verifications plus the number of rejected requests it *returned*
 * (capped), so the refusal total is `count` minus the returned rejections.
 * Explicit `violation_count` / `error_count` fields win when a Core sends
 * them.
 */
export function refusalTotals(v: PolicyViolations): RefusalTotals {
  const returnedErrors = v.error_violations?.length ?? 0;
  const refused = v.violation_count ?? Math.max(0, v.count - returnedErrors);
  if (v.error_count !== undefined) return { refused, rejected: v.error_count, rejectedAtLeast: false };
  return { refused, rejected: returnedErrors, rejectedAtLeast: returnedErrors >= ERROR_VIOLATIONS_CAP };
}

export interface TrailTotals {
  verifications: number;
  refused: number;
  /** Bound and descriptive together: the server has no whole-trail split. */
  approved: number;
}

/**
 * Whole-trail totals from the two polls. They are fetched separately, so a
 * verdict landing between them can skew the difference by one or two; it is
 * clamped so it never goes negative.
 */
export function trailTotals(h: ConfidenceHistory, v: PolicyViolations): TrailTotals {
  const { refused } = refusalTotals(v);
  return { verifications: h.count, refused, approved: Math.max(0, h.count - refused) };
}

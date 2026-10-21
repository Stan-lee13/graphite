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

import type { ConfidenceHistory, ConfidencePoint, PolicyViolations } from "./api";

export type VerdictKind = "bound" | "descriptive" | "refused";

export function verdictKind(p: Pick<ConfidencePoint, "approved" | "transaction_sha256">): VerdictKind {
  if (!p.approved) return "refused";
  return p.transaction_sha256 ? "bound" : "descriptive";
}

/** CSS tone for a verdict kind; descriptive is amber, never green. */
export function verdictTone(kind: VerdictKind): "pass" | "warn" | "block" {
  return kind === "bound" ? "pass" : kind === "descriptive" ? "warn" : "block";
}

export function verdictLabel(kind: VerdictKind): string {
  return kind === "bound" ? "approved" : kind === "descriptive" ? "approved · descriptive" : "refused";
}

export interface WindowCounts {
  /** Points in the window the server returned. */
  n: number;
  bound: number;
  descriptive: number;
  refused: number;
}

export function countWindow(series: readonly ConfidencePoint[]): WindowCounts {
  const c: WindowCounts = { n: series.length, bound: 0, descriptive: 0, refused: 0 };
  for (const p of series) c[verdictKind(p)]++;
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

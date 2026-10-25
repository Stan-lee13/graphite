// What the console says about the Core's own state: the sidebar's one-line
// status, the System view's durability figures and the connection test's
// wording. Pure, with type-only imports, so it runs under Node for its tests
// (status.test.ts, `tsx --test`).
//
// Round 39 (dashboard audit against a live Core). Each of these drew a
// definite answer from a field nobody had read, or the wrong one:
//   - System drew a /health without an `audit` object as "Off — verdicts are
//     not being recorded", and one without `graph_persistence` as "Off": an
//     unread field drawn as a definite (and alarming) negative;
//   - System drew the trail green "Writing" while the Core reported appends
//     failing (`audit.writes_failed` > 0, the reason it is degraded);
//   - the connection test answered a /health that came back 500 or 429 with
//     "No answer from /health ... add this origin to GRAPHITE_CORS_ORIGINS",
//     advice that cannot help a Core that did answer;
//   - the sidebar called a Core whose /health answered 500 "unreachable".

import type { Health } from "./api";

export type Tone = "pass" | "block" | "warn" | "idle";

export interface Reading {
  value: string;
  tone: Tone;
  sub?: string;
}

const bytes = (n: number) =>
  n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KB` : `${(n / (1024 * 1024)).toFixed(1)} MB`;

const wholeOrNull = (v: unknown): number | null =>
  typeof v === "number" && Number.isInteger(v) && v >= 0 ? v : null;

/** The audit trail figure. Unread is "Not reported", never "Off". */
export function auditReading(h: Pick<Health, "audit">): Reading {
  const a = h.audit;
  if (a === undefined || a === null || typeof a !== "object" || typeof a.enabled !== "boolean") {
    return { value: "Not reported", tone: "warn", sub: "this Core's /health does not say" };
  }
  if (!a.enabled) return { value: "Off", tone: "warn", sub: "verdicts are not being recorded" };
  const failed = wholeOrNull(a.writes_failed);
  if (failed !== null && failed > 0) {
    return { value: "Failing", tone: "block", sub: `${failed.toLocaleString()} append(s) failed; the Core refuses verdicts it cannot record` };
  }
  const active = wholeOrNull(a.active_bytes);
  const archived = wholeOrNull(a.archive_count);
  return {
    value: "Writing",
    tone: "pass",
    sub:
      active === null || archived === null
        ? "size not reported"
        : `${bytes(active)} active, ${archived.toLocaleString()} archived`,
  };
}

/** The graph-snapshot figure. Unread is "Not reported", never "Off". */
export function persistenceReading(h: Pick<Health, "graph_persistence">): Reading {
  const g = h.graph_persistence;
  if (g === undefined || g === null || typeof g !== "object" || typeof g.enabled !== "boolean") {
    return { value: "Not reported", tone: "warn", sub: "this Core's /health does not say" };
  }
  if (!g.enabled) return { value: "Off", tone: "warn", sub: "earned evidence is lost on restart" };
  const ok = wholeOrNull(g.snapshots_ok);
  const failed = wholeOrNull(g.snapshots_failed);
  if (failed !== null && failed > 0) {
    return { value: "Failing", tone: "block", sub: g.last_error ?? `${failed.toLocaleString()} snapshot(s) failed` };
  }
  return { value: ok === null ? "On" : ok.toLocaleString(), tone: "pass", sub: ok === null ? "count not reported" : "snapshots written" };
}

/** The kinds of failure `ApiError` carries (api.ts), without importing it. */
export type FailureKind = "unauthorized" | "ratelimited" | "unavailable" | "server" | "network" | "malformed" | "insecure";

/** The connection test's first line when `/health` did not give a Core's report. */
export function reachProblem(kind: FailureKind | undefined, message: string | undefined): { text: string; corsHint: boolean } {
  // Only "no response at all" can be a CORS refusal: the browser hides the
  // answer from the page. Anything else is the Core (or what stands in its
  // place) answering, and its own message says what it answered.
  if (kind === undefined || kind === "network") {
    return { text: "No answer from /health. Check the address; if the Core is up, add this console's origin to GRAPHITE_CORS_ORIGINS.", corsHint: true };
  }
  return { text: message ?? "The Core answered /health with an error.", corsHint: false };
}

/** The connection, as the shell shows it. */
export type CoreState = "ok" | "degraded" | "unauthorized" | "down" | "erroring" | "connecting";

export function coreState(opts: {
  healthError: FailureKind | null;
  health: Pick<Health, "degraded"> | null;
  keyedError: FailureKind | null;
}): CoreState {
  const { healthError, health, keyedError } = opts;
  if (healthError !== null) return healthError === "network" || healthError === "insecure" ? "down" : "erroring";
  if (health === null) return "connecting";
  if (keyedError === "unauthorized") return "unauthorized";
  return health.degraded ? "degraded" : "ok";
}

export function coreLabel(core: CoreState): string {
  switch (core) {
    case "ok":
      return "Core operational";
    case "degraded":
      return "Core degraded";
    case "unauthorized":
      return "Key rejected";
    case "down":
      return "Core unreachable";
    case "erroring":
      return "Core answering with errors";
    case "connecting":
      return "Connecting…";
  }
}

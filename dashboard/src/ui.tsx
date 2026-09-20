// Presentational primitives shared by the views.
//
// These exist so state handling is consistent across every view: the same
// loading shape, the same empty language, the same way an identifier is shown
// and copied. Inconsistency between screens is what makes an interface feel
// assembled rather than designed.

import { useState, type ReactNode } from "react";
import { AlertTriangle, Check, Copy, Inbox, ServerCrash } from "lucide-react";

/** Ordered low → high. Index is the tier's rank, which drives the scale. */
const TIER_ORDER = [
  "Unknown",
  "HeuristicInferred",
  "OfficialManifest",
  "SimulationValidated",
  "CommunityVerified",
  "BattleTested",
] as const;

/** Human label — the wire format is PascalCase, which reads poorly in prose. */
const TIER_LABEL: Record<string, string> = {
  Unknown: "Unknown",
  HeuristicInferred: "Heuristic",
  OfficialManifest: "Manifest",
  SimulationValidated: "Simulated",
  CommunityVerified: "Community",
  BattleTested: "Battle-tested",
};

export function tierRank(tier: string): number {
  const i = TIER_ORDER.indexOf(tier as (typeof TIER_ORDER)[number]);
  return i < 0 ? 0 : i;
}

/**
 * Trust tier as a filled scale rather than a coloured word.
 *
 * Tier is ordinal — earned evidence accumulates from Unknown up to
 * Battle-tested — so it is drawn as a scale. Rank stays legible while
 * scanning a column of thirty rows without reading a single label, which a
 * pill of coloured text does not achieve.
 */
export function TierBadge({ tier }: { tier: string }) {
  const rank = tierRank(tier);
  return (
    <span className={`tier tier-${rank}`} title={`${tier} (tier ${rank} of 5)`}>
      <span className="tier-bar" aria-hidden="true">
        {TIER_ORDER.map((_, i) => (
          <span key={i} className={i <= rank ? "tier-seg on" : "tier-seg"} />
        ))}
      </span>
      <span className="tier-name">{TIER_LABEL[tier] ?? tier}</span>
    </span>
  );
}

export type Tone = "pass" | "block" | "warn" | "idle";

export function State({ kind, children }: { kind: Tone; children: ReactNode }) {
  return <span className={`state ${kind}`}>{children}</span>;
}

/** Shorten a base58 identifier, keeping both ends recognisable. */
export function shortId(id: string, head = 8, tail = 6): string {
  if (id.length <= head + tail + 1) return id;
  return `${id.slice(0, head)}…${id.slice(-tail)}`;
}

/**
 * An identifier that can be copied.
 *
 * Program IDs and audit trail IDs exist to be pasted into an explorer or a
 * support ticket. Truncating them without offering the full value back would
 * make the display actively obstructive.
 */
export function CopyId({ value, short = true }: { value: string; short?: boolean }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className={copied ? "copy copied" : "copy"}
      title={copied ? "Copied" : `${value} — click to copy`}
      onClick={() => {
        void navigator.clipboard?.writeText(value).then(
          () => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          },
          () => {
            /* clipboard unavailable (insecure origin) — the title still shows
               the full value, so the user is not stuck */
          },
        );
      }}
    >
      {copied ? "copied" : short ? shortId(value) : value}
      {copied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
    </button>
  );
}

/**
 * A loading placeholder shaped like the table it replaces, so nothing jumps
 * when data arrives.
 */
export function TableSkeleton({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  // Varied widths read as data rather than as a progress bar.
  const widths = ["38%", "22%", "16%", "12%", "18%", "14%", "20%"];
  return (
    <div aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }).map((_, r) => (
        <div className="skeleton-row" key={r}>
          {Array.from({ length: cols }).map((_, c) => (
            <div
              className="skeleton-bar"
              key={c}
              style={{
                width: widths[(r + c) % widths.length],
                // Stagger so the sweep does not pulse in lockstep.
                animationDelay: `${((r * cols + c) % 7) * 90}ms`,
              }}
            />
          ))}
        </div>
      ))}
    </div>
  );
}

/**
 * Empty state. Says what is absent and what would fill it — an empty table
 * with no explanation is indistinguishable from a broken one.
 */
export function Empty({ title, hint }: { title: string; hint?: ReactNode }) {
  return (
    <div className="note">
      <span className="note-icon" aria-hidden="true">
        <Inbox />
      </span>
      <strong>{title}</strong>
      {hint}
    </div>
  );
}

/** Failure state, with the one action that usually resolves it. */
export function ErrorState({ message }: { message: string }) {
  return (
    <div className="note error" role="alert">
      <span className="note-icon" aria-hidden="true">
        <ServerCrash />
      </span>
      <strong>Cannot reach the Core</strong>
      {message}
      <div style={{ marginTop: 10 }}>
        Start it with <code>cargo run --bin graphite -- server</code>, or point{" "}
        <code>VITE_GRAPHITE_API</code> at a running instance.
      </div>
    </div>
  );
}

/** A warning callout inside a panel. */
export function Callout({ children }: { children: ReactNode }) {
  return (
    <div className="note" style={{ padding: "18px 16px", textAlign: "left", alignItems: "flex-start", flexDirection: "row", gap: 12 }}>
      <span className="note-icon" style={{ marginBottom: 0, flex: "none" }} aria-hidden="true">
        <AlertTriangle />
      </span>
      <div>{children}</div>
    </div>
  );
}

/** One figure in the stat row. */
export function Metric({
  label,
  value,
  sub,
  tone,
  icon,
}: {
  label: string;
  value: ReactNode;
  sub?: string;
  tone?: Tone;
  icon?: ReactNode;
}) {
  return (
    <div className="metric">
      <span className="metric-label">
        {icon}
        {label}
      </span>
      <span className={tone ? `metric-value ${tone}` : "metric-value"}>{value}</span>
      {sub && <span className="metric-sub">{sub}</span>}
    </div>
  );
}

/** View header: title, description, optional note, and the stat row. */
export function ViewHead({
  title,
  desc,
  note,
  children,
}: {
  title: string;
  desc?: ReactNode;
  note?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <header className="view-head">
      <div className="view-title">
        <div>
          <h2>{title}</h2>
          {desc && <p className="view-desc">{desc}</p>}
        </div>
        {note && <span className="view-note">{note}</span>}
      </div>
      {children && <div className="metrics">{children}</div>}
    </header>
  );
}

export function Panel({
  title,
  icon,
  meta,
  children,
  flush,
}: {
  title: string;
  icon?: ReactNode;
  meta?: ReactNode;
  children: ReactNode;
  /** Tables sit flush to the panel edge; prose gets padding. */
  flush?: boolean;
}) {
  return (
    <section className="panel">
      <div className="panel-head">
        <h3>
          {icon}
          {title}
        </h3>
        {meta && <span className="meta">{meta}</span>}
      </div>
      {flush ? <div className="table-wrap">{children}</div> : <div className="panel-body">{children}</div>}
    </section>
  );
}

/** Compact absolute time. Locale date strings are too wide for a data column. */
export function shortTime(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(
    d.getMinutes(),
  )}:${pad(d.getSeconds())}`;
}

/** Relative time, for "how fresh is this" rather than "exactly when". */
export function relTime(ts: string): string {
  const d = new Date(ts).getTime();
  if (Number.isNaN(d)) return "";
  const secs = Math.max(0, Math.round((Date.now() - d) / 1000));
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
  return `${Math.round(secs / 86400)}d ago`;
}

// Presentational primitives shared by the views.
//
// These exist so state handling is consistent across every screen: the same
// loading shape, the same empty language, the same way an identifier is shown
// and copied, the same three fault states. Inconsistency between screens is
// what makes an interface feel assembled rather than designed.

import { useEffect, useRef, useState, type ReactNode } from "react";
import { Check, Copy, Inbox, KeyRound, PlugZap, ServerCrash, X } from "lucide-react";
import { ApiError } from "./api";
import { hrefFor } from "./router";

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
export const TIER_LABEL: Record<string, string> = {
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
 * Trust tier as six stacked layers, lit from the bottom up.
 *
 * Tier is ordinal — evidence accumulates from Unknown to Battle-tested — so
 * it is drawn as a scale, and the scale is drawn as layers because that is
 * what the material is. Rank stays legible while scanning thirty rows without
 * reading a label.
 */
export function TierBadge({ tier, compact = false }: { tier: string; compact?: boolean }) {
  const rank = tierRank(tier);
  return (
    <span className="tier" title={`${TIER_LABEL[tier] ?? tier}, tier ${rank} of 5`}>
      <span className="tier-layers" aria-hidden="true">
        {TIER_ORDER.map((_, i) => (
          <i key={i} className={i <= rank ? "on" : undefined} />
        ))}
      </span>
      {!compact && <span className="tier-name">{TIER_LABEL[tier] ?? tier}</span>}
    </span>
  );
}

export type Tone = "pass" | "block" | "warn" | "idle" | "brand";

export function State({ kind, children, title }: { kind: Tone; children: ReactNode; title?: string }) {
  return (
    <span className={`state ${kind}`} title={title}>
      {children}
    </span>
  );
}

/** Shorten a base58 identifier, keeping both ends recognisable. */
export function shortId(id: string, head = 6, tail = 4): string {
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
export function CopyId({
  value,
  short = true,
  head,
  tail,
}: {
  value: string;
  short?: boolean;
  head?: number;
  tail?: number;
}) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout>>();
  useEffect(() => () => clearTimeout(timer.current), []);
  return (
    <button
      type="button"
      className={copied ? "copy copied" : "copy"}
      title={copied ? "Copied" : `Copy ${value}`}
      aria-label={copied ? "Copied" : `Copy ${value}`}
      translate="no"
      onClick={() => {
        void navigator.clipboard?.writeText(value).then(
          () => {
            setCopied(true);
            timer.current = setTimeout(() => setCopied(false), 1200);
          },
          () => {
            /* clipboard unavailable on an insecure origin; the title still
               carries the full value, so nobody is stuck */
          },
        );
      }}
    >
      <span className="copy-text">{copied ? "Copied" : short ? shortId(value, head, tail) : value}</span>
      {copied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
    </button>
  );
}

/** A loading placeholder shaped like the content it replaces. */
export function Skeleton({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  // Varied widths read as data rather than as a progress bar.
  const widths = ["38%", "22%", "16%", "12%", "18%", "14%", "20%"];
  return (
    <div className="skeleton" aria-busy="true" aria-label="Loading…">
      {Array.from({ length: rows }).map((_, r) => (
        <div className="skeleton-row" key={r}>
          {Array.from({ length: cols }).map((_, c) => (
            <span
              className="skeleton-bar"
              key={c}
              style={{
                width: widths[(r + c) % widths.length],
                animationDelay: `${((r * cols + c) % 7) * 90}ms`,
              }}
            />
          ))}
        </div>
      ))}
    </div>
  );
}

/** Empty state: what is absent, and what would fill it. */
export function Empty({ title, hint }: { title: string; hint?: ReactNode }) {
  return (
    <div className="note">
      <Inbox className="note-icon" aria-hidden="true" />
      <strong>{title}</strong>
      {hint && <p>{hint}</p>}
    </div>
  );
}

/**
 * Failure state, keyed on what actually failed. A rejected key and a Core
 * that is down are different problems with different fixes, and an
 * interface that shows the same red box for both is hiding the one fact the
 * operator needs.
 */
export function Fault({ error }: { error: ApiError }) {
  if (error.kind === "unauthorized") {
    return (
      <div className="note fault" role="alert">
        <KeyRound className="note-icon" aria-hidden="true" />
        <strong>This Core needs a different key</strong>
        <p>
          It answered 401. The key in this browser is missing or is not the one the Core was started
          with.
        </p>
        <a className="btn primary" href={hrefFor("connect")}>
          Open connection settings
        </a>
      </div>
    );
  }
  if (error.kind === "insecure") {
    // Round 19 (F-19-C6): refused before anything was sent. The message
    // names the address and the fix.
    return (
      <div className="note fault" role="alert">
        <KeyRound className="note-icon" aria-hidden="true" />
        <strong>Not sending the key over plain http://</strong>
        <p>{error.message}</p>
        <a className="btn primary" href={hrefFor("connect")}>
          Open connection settings
        </a>
      </div>
    );
  }
  if (error.kind === "network") {
    return (
      <div className="note fault" role="alert">
        <PlugZap className="note-icon" aria-hidden="true" />
        <strong>No response from the Core</strong>
        <p>
          Either nothing is listening at the configured address, or the Core is up but refused this
          origin. A Core allows browsers only from the origins in{" "}
          <code translate="no">GRAPHITE_CORS_ORIGINS</code>.
        </p>
        <a className="btn primary" href={hrefFor("connect")}>
          Check the connection
        </a>
      </div>
    );
  }
  return (
    <div className="note fault" role="alert">
      <ServerCrash className="note-icon" aria-hidden="true" />
      <strong>
        {error.kind === "ratelimited"
          ? "Rate limited"
          : error.kind === "unavailable"
            ? "The Core is shedding load"
            : "The Core returned an error"}
      </strong>
      <p>
        {error.message} The console retries on its own; if this persists, the Core's log has the
        reason.
      </p>
    </div>
  );
}

/** One figure. Figures sit in a hairline row, not in cards. */
export function Figure({
  label,
  value,
  sub,
  tone,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  tone?: Tone;
}) {
  return (
    <div className="figure">
      <span className="figure-label">{label}</span>
      <span className={tone ? `figure-value ${tone}` : "figure-value"}>{value}</span>
      {sub !== undefined && <span className="figure-sub">{sub}</span>}
    </div>
  );
}

/** View header: title, one-sentence description, and actions. */
export function PageHead({
  title,
  desc,
  actions,
}: {
  title: string;
  desc?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="page-head">
      <div className="page-title">
        <h1>{title}</h1>
        {desc && <p>{desc}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}

/** A titled region. Tables sit flush to its edge; prose gets padding. */
export function Section({
  title,
  meta,
  children,
  flush,
  id,
}: {
  title: ReactNode;
  meta?: ReactNode;
  children: ReactNode;
  flush?: boolean;
  id?: string;
}) {
  return (
    <section className="section" id={id}>
      <div className="section-head">
        <h2>{title}</h2>
        {meta !== undefined && <div className="section-meta">{meta}</div>}
      </div>
      <div className={flush ? "section-flush" : "section-body"}>{children}</div>
    </section>
  );
}

/** A plain in-app link, drawn as a link. Navigation is `<a>`, never a div. */
export function Jump({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a className="jump" href={href}>
      {children}
    </a>
  );
}

/**
 * A detail pane. On a desktop it slides in from the right over the content;
 * on a phone it rises as a sheet from the bottom. Same content, two
 * anatomies — the caller never branches.
 */
export function Detail({
  open,
  onClose,
  title,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    // Move focus into the pane so a keyboard user lands where the content is.
    ref.current?.focus();
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <>
      <div className="scrim" onClick={onClose} aria-hidden="true" />
      <div className="detail" role="dialog" aria-modal="true" aria-label={typeof title === "string" ? title : "Details"} ref={ref} tabIndex={-1}>
        <div className="detail-head">
          <div className="detail-title">{title}</div>
          <button type="button" className="icon-btn" onClick={onClose} aria-label="Close">
            <X aria-hidden="true" />
          </button>
        </div>
        <div className="detail-body">{children}</div>
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------
// Formatting, through Intl so it follows the viewer's locale.

const num = new Intl.NumberFormat(undefined);
const dec2 = new Intl.NumberFormat(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const clock = new Intl.DateTimeFormat(undefined, {
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
});
const rel = new Intl.RelativeTimeFormat(undefined, { numeric: "always", style: "narrow" });

export const fmt = {
  int: (n: number) => num.format(n),
  score: (n: number) => dec2.format(n),
  pct: (n: number) => `${Math.round(n * 100)}%`,
  bytes: (n: number) =>
    n < 1024
      ? `${n} B`
      : n < 1024 * 1024
        ? `${(n / 1024).toFixed(1)} KB`
        : `${(n / (1024 * 1024)).toFixed(1)} MB`,
};

/** Compact absolute time in the viewer's locale. */
export function shortTime(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return clock.format(d);
}

/** Relative time, for "how fresh is this" rather than "exactly when". */
export function relTime(ts: string | number): string {
  const d = typeof ts === "number" ? ts : new Date(ts).getTime();
  if (Number.isNaN(d)) return "";
  const secs = Math.round((d - Date.now()) / 1000);
  const a = Math.abs(secs);
  if (a < 60) return rel.format(secs, "second");
  if (a < 3600) return rel.format(Math.round(secs / 60), "minute");
  if (a < 86400) return rel.format(Math.round(secs / 3600), "hour");
  return rel.format(Math.round(secs / 86400), "day");
}

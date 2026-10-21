// The first screen: is the gate healthy, what did it just decide, and did
// anything get past it. Everything here is derived from the same read-only
// endpoints the deeper views poll — it introduces no new data source, only a
// first look that answers those three questions before a single click.

import { useEffect, useRef, useState } from "react";
import { Siren } from "lucide-react";
import { api, type ConfidencePoint, type Metrics } from "../api";
import { countWindow, refusalTotals, trailTotals, verdictKind, verdictLabel, verdictTone, windowLabel } from "../figures";
import { hrefFor } from "../router";
import { usePolling, useReducedMotion, type Polled } from "../usePolling";
import {
  CopyId,
  Empty,
  Fault,
  Figure,
  Freshness,
  Jump,
  PageHead,
  Section,
  Skeleton,
  State,
  TierBadge,
  fmt,
  pollFault,
  relTime,
  tierRank,
} from "../ui";

/** How many recent verdicts the tape shows. */
const TAPE = 120;

/**
 * Counters whose first non-zero value is a page. Each one means a decision
 * the gate made was not the decision that happened, or the record of it is
 * in doubt. The Core names them "page on this" in its own metric help text.
 */
const PAGE_ON: { metric: string; label: string }[] = [
  { metric: "graphite_execution_discrepancies_total", label: "blocked transactions that executed on-chain" },
  { metric: "graphite_lifecycle_events_on_blocked_total", label: "signing or submission reports for blocked transactions" },
  { metric: "graphite_execution_chain_bytes_rejected_total", label: "RPC answers whose bytes did not match the signature" },
  { metric: "graphite_execution_chain_inconsistent_total", label: "RPC answers that contradicted themselves" },
  { metric: "graphite_execution_witness_disagreements_total", label: "witness disagreements about inclusion" },
  { metric: "graphite_lifecycle_sequence_anomalies_total", label: "lifecycle reports out of order or contradictory" },
];

export function OverviewView() {
  const graph = usePolling(() => api.graph(), 5000);
  const top = usePolling(() => api.topProtocols(), 5000);
  const history = usePolling(() => api.confidenceHistory(), 5000);
  const violations = usePolling(() => api.policyViolations(), 5000);
  const metrics = usePolling(() => api.metrics(), 10000);

  const fault = pollFault(graph, top, history, violations);
  if (fault) return <Fault error={fault} />;

  const loading = !graph.data || !top.data || !history.data || !violations.data;

  const nodes = graph.data?.nodes ?? [];
  const trusted = nodes.filter((n) => tierRank(n.trust_tier) >= 3).length;
  const quarantined = nodes.filter((n) => n.quarantined).length;

  // Round 29 (audit 2026-10-20, D1/D4): whole-trail totals from the server's
  // counts; the split into bound and descriptive approvals exists only for
  // the window the server returned, and the label says so.
  const series = history.data?.series ?? [];
  const totals = history.data && violations.data ? trailTotals(history.data, violations.data) : null;
  const rejections = violations.data ? refusalTotals(violations.data) : null;
  const win = countWindow(series);
  const winLabel = windowLabel(win.n, history.data?.count ?? win.n);
  const latest = series[series.length - 1];

  const blocked = violations.data?.violations ?? [];
  const recentBlocked = [...blocked]
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, 6);

  // `/api/protocols/top` reports observed counts for its five rows only; a
  // program outside them has an unknown count here, not a zero (D10).
  const observedBy = new Map((top.data?.top ?? []).map((t) => [t.program_id, t.observed_verifications]));
  const topRows = [...nodes]
    .map((node) => ({ node, observed: observedBy.get(node.program_id) }))
    .sort((a, b) => (b.observed ?? -1) - (a.observed ?? -1) || b.node.battle_tested_tx_count - a.node.battle_tested_tx_count)
    .slice(0, 6);

  const nameOf = new Map(nodes.map((n) => [n.program_id, n.name]));

  return (
    <>
      <PageHead
        title="Overview"
        desc={
          loading || !totals
            ? "Loading…"
            : `${fmt.int(totals.verifications)} verifications on record across ${fmt.int(nodes.length)} programs.`
        }
      />

      <Freshness sources={[graph, top, history, violations]} />

      <Attention metrics={metrics} />

      <div className="figures five">
        <Figure
          label="Approved"
          value={loading || !totals ? "—" : fmt.int(totals.approved)}
          sub={loading || !totals ? undefined : "all time, bound and descriptive"}
        />
        <Figure
          label="Refused"
          value={loading || !totals ? "—" : fmt.int(totals.refused)}
          sub={
            loading || !rejections
              ? undefined
              : `all time; ${rejections.rejectedAtLeast ? "≥ " : ""}${fmt.int(rejections.rejected)} malformed`
          }
          tone={totals && totals.refused > 0 ? "block" : "idle"}
        />
        <Figure
          label={`Bound to bytes, ${winLabel}`}
          value={loading ? "—" : fmt.int(win.bound)}
          sub={loading || !win.n ? undefined : `${fmt.pct(win.bound / win.n)} of those verdicts`}
          tone={win.bound > 0 ? "pass" : "idle"}
        />
        <Figure
          label={`Descriptive, ${winLabel}`}
          value={loading ? "—" : fmt.int(win.descriptive)}
          sub="approved as described, no bytes"
          tone={win.descriptive > 0 ? "warn" : "idle"}
        />
        <Figure
          label="Programs"
          value={loading ? "—" : fmt.int(nodes.length)}
          sub={loading ? undefined : `${trusted} at tier 3+, ${quarantined} quarantined`}
          tone={quarantined > 0 ? "warn" : undefined}
        />
      </div>

      <Section
        title="Verdicts"
        meta={
          loading ? undefined : latest ? (
            <span className="latest">
              Latest {relTime(latest.timestamp)}: <strong>{nameOf.get(latest.program_id) ?? latest.program_id}</strong>,{" "}
              <State kind={verdictTone(verdictKind(latest))}>{verdictLabel(verdictKind(latest))}</State> at{" "}
              <span className="num">{fmt.score(latest.confidence)}</span>
            </span>
          ) : undefined
        }
      >
        {loading ? (
          <Skeleton rows={1} cols={1} />
        ) : series.length === 0 ? (
          <Empty title="No verdicts yet" hint="The first transaction posted to /verify appears here the moment the trail records it." />
        ) : (
          <Tape points={series.slice(-TAPE)} total={history.data?.count ?? series.length} />
        )}
      </Section>

      <div className="two-up">
        <Section
          title="Refused lately"
          meta={loading ? undefined : <Jump href={hrefFor("blocked")}>All refusals</Jump>}
          flush
        >
          {loading ? (
            <Skeleton rows={5} cols={3} />
          ) : recentBlocked.length === 0 ? (
            <Empty title="Nothing refused" hint="No refusal is on the trail." />
          ) : (
            <ul className="rows">
              {recentBlocked.map((v) => (
                <li key={v.audit_trail_id} className="row">
                  <div className="row-main">
                    <span className="row-title">
                      {v.protocol_name} <span className="row-sub">{v.instruction_name}</span>
                    </span>
                    <span className="row-meta">
                      <CopyId value={v.program_id} />
                      <span>{relTime(v.timestamp)}</span>
                    </span>
                  </div>
                  <div className="row-side">
                    <span className="num muted">{fmt.score(v.confidence)}</span>
                    {v.risk_status === "Blocked" ? (
                      <State kind="block">risk</State>
                    ) : (
                      // Risk was clear; POLICY refused — the confidence sat under
                      // the profile's floor. A different refusal, drawn differently.
                      <State kind="warn" title={`Risk ${v.risk_status}, rejected by policy (${v.policy_verdict})`}>
                        policy
                      </State>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section
          title="Most exercised"
          meta={loading ? undefined : <Jump href={hrefFor("programs")}>All programs</Jump>}
          flush
        >
          {loading ? (
            <Skeleton rows={5} cols={3} />
          ) : topRows.length === 0 ? (
            <Empty title="No programs" hint="Seed manifests load at startup. An empty graph means the Core failed to boot its registry." />
          ) : (
            <ul className="rows">
              {topRows.map(({ node, observed }) => (
                <li key={node.program_id} className="row">
                  <a className="row-main" href={hrefFor("programs", node.program_id)}>
                    <span className="row-title">{node.name}</span>
                    <span className="row-meta">
                      <span translate="no">
                        {observed === undefined
                          ? `${fmt.int(node.battle_tested_tx_count)} in the mainnet census`
                          : observed > 0
                            ? `${fmt.int(observed)} verifications`
                            : "not verified here yet"}
                      </span>
                    </span>
                  </a>
                  <div className="row-side">
                    {node.quarantined ? <State kind="block">quarantined</State> : <TierBadge tier={node.trust_tier} />}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Section>
      </div>
    </>
  );
}

/**
 * Red band when any bypass counter is non-zero; nothing at all when every
 * counter was read and is zero.
 *
 * Round 29 (audit 2026-10-20, D2): the band was fed by a `/metrics` poll
 * whose error was never looked at, so when `/metrics` failed (a 401, a
 * proxy that does not forward it, a Core shedding load) the band simply was
 * not there — which reads as "all clear". An unread counter is not a zero:
 * the band now says the state is unknown, and why, until a read succeeds.
 */
function Attention({ metrics }: { metrics: Polled<Metrics> }) {
  const m = metrics.data;
  const hits = m ? PAGE_ON.map((p) => ({ ...p, n: m.get(p.metric) ?? 0 })).filter((p) => p.n > 0) : [];
  if (metrics.error) {
    return (
      <div className={hits.length > 0 ? "banner block" : "banner warn"} role="alert">
        <Siren aria-hidden="true" />
        <div>
          <strong>Bypass signals: unknown — /metrics unavailable.</strong> {metrics.error.message}
          {hits.length > 0 && (
            <ul>
              {hits.map((h) => (
                <li key={h.metric}>
                  at the last good read: <span className="num">{fmt.int(h.n)}</span> {h.label}
                </li>
              ))}
            </ul>
          )}
        </div>
        <a className="btn small" href={hrefFor("system")}>
          System
        </a>
      </div>
    );
  }
  if (!m || hits.length === 0) return null;
  return (
    <div className="banner block" role="alert">
      <Siren aria-hidden="true" />
      <div>
        <strong>The gate's record is in doubt.</strong>
        <ul>
          {hits.map((h) => (
            <li key={h.metric}>
              <span className="num">{fmt.int(h.n)}</span> {h.label}
            </li>
          ))}
        </ul>
      </div>
      <a className="btn small" href={hrefFor("system")}>
        System
      </a>
    </div>
  );
}

/**
 * The verdict tape. Every recent verification is one slat, edge on: height
 * is confidence, colour is the verdict, and a new slat slides in from the
 * right when the trail grows. It is the one thing on the page that moves,
 * and it moves only when the gate has decided something.
 */
function Tape({ points, total }: { points: ConfidencePoint[]; total: number }) {
  const reduced = useReducedMotion();
  const lastSeen = useRef(total);
  const [fresh, setFresh] = useState(0);

  useEffect(() => {
    const added = total - lastSeen.current;
    lastSeen.current = total;
    if (added > 0 && !reduced) {
      setFresh(added);
      const t = setTimeout(() => setFresh(0), 700);
      return () => clearTimeout(t);
    }
  }, [total, reduced]);

  const n = points.length;
  return (
    <div className="tape-wrap">
      <ol className="tape" aria-label={`The last ${n} verdicts, oldest first; green is bound to bytes, amber descriptive, red refused`}>
        {points.map((p, i) => (
          <li
            key={p.audit_trail_id}
            className={`slat ${verdictTone(verdictKind(p))}${i >= n - fresh ? " fresh" : ""}`}
            style={{ ["--h" as string]: `${Math.max(8, Math.round(p.confidence * 100))}%` }}
            title={`${fmt.score(p.confidence)}, ${verdictLabel(verdictKind(p))}, ${relTime(p.timestamp)}`}
          />
        ))}
      </ol>
      <div className="tape-axis" aria-hidden="true">
        <span>{relTime(points[0].timestamp)}</span>
        <span>now</span>
      </div>
    </div>
  );
}

// The first screen: is the gate healthy, what did it just decide, and did
// anything get past it. Everything here is derived from the same read-only
// endpoints the deeper views poll — it introduces no new data source, only a
// first look that answers those three questions before a single click.

import { useEffect, useRef, useState } from "react";
import { Siren } from "lucide-react";
import { api, type ConfidencePoint, type Metrics } from "../api";
import { hrefFor } from "../router";
import { usePolling, useReducedMotion } from "../usePolling";
import {
  CopyId,
  Empty,
  Fault,
  Figure,
  Jump,
  PageHead,
  Section,
  Skeleton,
  State,
  TierBadge,
  fmt,
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

  const error = graph.error ?? top.error ?? history.error ?? violations.error;
  if (error) return <Fault error={error} />;

  const loading = !graph.data || !top.data || !history.data || !violations.data;

  const nodes = graph.data?.nodes ?? [];
  const trusted = nodes.filter((n) => tierRank(n.trust_tier) >= 3).length;
  const quarantined = nodes.filter((n) => n.quarantined).length;

  const series = history.data?.series ?? [];
  const approved = series.filter((p) => p.approved).length;
  const refused = series.length - approved;
  const latest = series[series.length - 1];

  const blocked = violations.data?.violations ?? [];
  const malformed = violations.data?.error_violations ?? [];
  const recentBlocked = [...blocked]
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, 6);

  const observedBy = new Map((top.data?.top ?? []).map((t) => [t.program_id, t.observed_verifications]));
  const topRows = [...nodes]
    .map((node) => ({ node, observed: observedBy.get(node.program_id) ?? 0 }))
    .sort((a, b) => b.observed - a.observed || b.node.battle_tested_tx_count - a.node.battle_tested_tx_count)
    .slice(0, 6);

  const nameOf = new Map(nodes.map((n) => [n.program_id, n.name]));

  return (
    <>
      <PageHead
        title="Overview"
        desc={
          loading
            ? "Loading…"
            : `${fmt.int(series.length)} verifications on record across ${fmt.int(nodes.length)} programs.`
        }
      />

      <Attention metrics={metrics.data} />

      <div className="figures">
        <Figure label="Approved" value={loading ? "—" : fmt.int(approved)} sub={loading || !series.length ? undefined : fmt.pct(approved / series.length)} tone="pass" />
        <Figure
          label="Refused"
          value={loading ? "—" : fmt.int(refused)}
          sub={loading ? undefined : `${fmt.int(malformed.length)} malformed`}
          tone={refused > 0 ? "block" : "idle"}
        />
        <Figure label="Programs" value={loading ? "—" : fmt.int(nodes.length)} sub={loading ? undefined : `${trusted} at tier 3 or above`} />
        <Figure
          label="Quarantined"
          value={loading ? "—" : fmt.int(quarantined)}
          sub={loading ? undefined : quarantined === 0 ? "none isolated" : "withdrawn from trust"}
          tone={quarantined > 0 ? "warn" : "idle"}
        />
      </div>

      <Section
        title="Verdicts"
        meta={
          loading ? undefined : latest ? (
            <span className="latest">
              Latest {relTime(latest.timestamp)}: <strong>{nameOf.get(latest.program_id) ?? latest.program_id}</strong>,{" "}
              {latest.approved ? <State kind="pass">approved</State> : <State kind="block">refused</State>} at{" "}
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
          <Tape points={series.slice(-TAPE)} total={series.length} />
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
            <Empty title="Nothing refused" hint="Every verification on record was approved." />
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
                      <span translate="no">{observed > 0 ? `${fmt.int(observed)} verifications` : "no traffic yet"}</span>
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

/** Red band when any bypass counter is non-zero; nothing at all otherwise. */
function Attention({ metrics }: { metrics: Metrics | null }) {
  if (!metrics) return null;
  const hits = PAGE_ON.map((p) => ({ ...p, n: metrics.get(p.metric) ?? 0 })).filter((p) => p.n > 0);
  if (hits.length === 0) return null;
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
      <ol className="tape" aria-label={`The last ${n} verdicts, oldest first`}>
        {points.map((p, i) => (
          <li
            key={p.audit_trail_id}
            className={`slat ${p.approved ? "pass" : "block"}${i >= n - fresh ? " fresh" : ""}`}
            style={{ ["--h" as string]: `${Math.max(8, Math.round(p.confidence * 100))}%` }}
            title={`${fmt.score(p.confidence)}, ${p.approved ? "approved" : "refused"}, ${relTime(p.timestamp)}`}
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

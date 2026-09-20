// The landing view: the handful of numbers an operator checks first, and the
// two lists they will open next. Everything here is derived from the same
// read-only endpoints the deeper views poll — it introduces no new data
// source, only a first screen that answers "is the gate healthy, and did it
// refuse anything" before a single click.

import { ArrowRight, Boxes, Gauge, ShieldBan, ShieldCheck } from "lucide-react";
import { usePolling } from "../usePolling";
import { api } from "../api";
import type { Tab } from "../App";
import {
  CopyId,
  Empty,
  ErrorState,
  Metric,
  Panel,
  State,
  TableSkeleton,
  TierBadge,
  ViewHead,
  relTime,
  tierRank,
} from "../ui";

/** How many recent verifications the sparkline and the outcome strip show. */
const WINDOW = 80;

export function OverviewView({ onNavigate }: { onNavigate: (t: Tab) => void }) {
  const graph = usePolling(() => api.graph(), 5000);
  const top = usePolling(() => api.topProtocols(), 5000);
  const history = usePolling(() => api.confidenceHistory(), 5000);
  const violations = usePolling(() => api.policyViolations(), 5000);

  const error = graph.error ?? top.error ?? history.error ?? violations.error;
  if (error) return <ErrorState message={error} />;

  const loading = !graph.data || !top.data || !history.data || !violations.data;

  const nodes = graph.data?.nodes ?? [];
  const trusted = nodes.filter((n) => tierRank(n.trust_tier) >= 3).length;
  const quarantined = nodes.filter((n) => n.quarantined).length;

  const series = history.data?.series ?? [];
  const recent = series.slice(-WINDOW);
  const approvedRate =
    series.length === 0
      ? null
      : Math.round((series.filter((p) => p.approved).length / series.length) * 100);
  const meanConfidence =
    recent.length === 0
      ? null
      : recent.reduce((s, p) => s + p.confidence, 0) / recent.length;

  const blocked = violations.data?.violations ?? [];
  const errors = violations.data?.error_violations ?? [];
  const recentBlocked = [...blocked]
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, 6);

  const observedBy = new Map(
    (top.data?.top ?? []).map((t) => [t.program_id, t.observed_verifications]),
  );
  const topRows = [...nodes]
    .map((node) => ({ node, observed: observedBy.get(node.program_id) ?? 0 }))
    .sort(
      (a, b) =>
        b.observed - a.observed ||
        b.node.battle_tested_tx_count - a.node.battle_tested_tx_count,
    )
    .slice(0, 6);

  return (
    <>
      <ViewHead
        title="Overview"
        desc="Live state of the verification gate: what it knows, what it has approved, and what it has refused."
        note={loading ? "loading" : `${series.length.toLocaleString()} verifications on record`}
      >
        <Metric
          label="Programs in graph"
          icon={<Boxes />}
          value={loading ? "—" : nodes.length}
          sub={loading ? undefined : `${trusted} at trust tier 3+`}
        />
        <Metric
          label="Approval rate"
          icon={<ShieldCheck />}
          value={loading ? "—" : approvedRate === null ? "—" : `${approvedRate}%`}
          sub={
            loading || meanConfidence === null
              ? "no verifications yet"
              : `mean confidence ${meanConfidence.toFixed(2)} over last ${recent.length}`
          }
          tone={!loading && approvedRate === null ? "idle" : undefined}
        />
        <Metric
          label="Blocked"
          icon={<ShieldBan />}
          value={loading ? "—" : blocked.length}
          sub={loading ? undefined : `${errors.length} rejected as malformed`}
          tone={blocked.length > 0 ? "block" : "idle"}
        />
        <Metric
          label="Quarantined"
          icon={<Gauge />}
          value={loading ? "—" : quarantined}
          sub={loading ? undefined : quarantined === 0 ? "no programs isolated" : "programs isolated"}
          tone={quarantined > 0 ? "warn" : "idle"}
        />
      </ViewHead>

      <div className="body">
        <Panel
          title="Confidence, recent"
          icon={<Gauge />}
          meta={loading ? "" : recent.length === 0 ? "no data" : `last ${recent.length} · green passed, red blocked`}
        >
          {loading ? (
            <TableSkeleton rows={2} cols={1} />
          ) : recent.length === 0 ? (
            <Empty
              title="No verifications yet"
              hint="Confidence appears here as soon as the Core records its first verification."
            />
          ) : (
            <Sparkline points={recent} />
          )}
        </Panel>

        <div className="grid-2">
          <Panel
            title="Recently blocked"
            icon={<ShieldBan />}
            meta={
              loading ? (
                ""
              ) : (
                <JumpLink onClick={() => onNavigate("violations")}>all blocked</JumpLink>
              )
            }
            flush
          >
            {loading ? (
              <TableSkeleton rows={5} cols={3} />
            ) : recentBlocked.length === 0 ? (
              <Empty
                title="Nothing blocked"
                hint="Every verification on record was approved by policy."
              />
            ) : (
              <ul className="list">
                {recentBlocked.map((v) => (
                  <li key={v.audit_trail_id}>
                    <div className="l">
                      <span className="primary">
                        {v.protocol_name}
                        <span className="secondary">{v.instruction_name}</span>
                      </span>
                      <span className="sub">
                        <CopyId value={v.program_id} /> · {relTime(v.timestamp)}
                      </span>
                    </div>
                    <div className="r">
                      <span className="mono" style={{ color: "var(--fg-3)", fontSize: 12 }}>
                        {v.confidence.toFixed(2)}
                      </span>
                      {v.risk_status === "Blocked" ? (
                        <State kind="block">blocked</State>
                      ) : (
                        // Risk was clear; it was POLICY that refused — the
                        // confidence sat under the profile's floor. A
                        // different refusal, drawn in a different colour.
                        <span title={`risk ${v.risk_status} · rejected by policy (${v.policy_verdict})`}>
                          <State kind="warn">policy</State>
                        </span>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel
            title="Most exercised programs"
            icon={<Boxes />}
            meta={
              loading ? (
                ""
              ) : (
                <JumpLink onClick={() => onNavigate("protocols")}>all programs</JumpLink>
              )
            }
            flush
          >
            {loading ? (
              <TableSkeleton rows={5} cols={3} />
            ) : topRows.length === 0 ? (
              <Empty
                title="No programs in the graph"
                hint="Seed manifests load at startup — if this is empty the Core may have failed to boot its registry."
              />
            ) : (
              <ul className="list">
                {topRows.map(({ node, observed }) => (
                  <li key={node.program_id}>
                    <div className="l">
                      <span className="primary">{node.name}</span>
                      <span className="sub">
                        <CopyId value={node.program_id} />
                        {observed > 0 && <> · {observed.toLocaleString()} observed</>}
                      </span>
                    </div>
                    <div className="r">
                      {node.quarantined ? (
                        <State kind="block">quarantined</State>
                      ) : (
                        <TierBadge tier={node.trust_tier} />
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      </div>
    </>
  );
}

function JumpLink({ onClick, children }: { onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      className="copy"
      onClick={onClick}
      style={{ fontFamily: "var(--sans)", fontSize: 12, color: "var(--brand)" }}
    >
      {children}
      <ArrowRight style={{ opacity: 1, color: "inherit" }} aria-hidden="true" />
    </button>
  );
}

/**
 * Confidence over the recent window, drawn as a line with an outcome strip
 * beneath it. Blocked points are marked on the line, and the strip repeats
 * the outcome as a bar so a run of refusals is visible as a block of red
 * without reading a single dot.
 */
function Sparkline({
  points,
}: {
  points: { confidence: number; approved: boolean; timestamp: string }[];
}) {
  const W = 1000;
  const H = 72;
  const pad = 4;
  const n = points.length;
  const x = (i: number) => (n === 1 ? W / 2 : pad + (i / (n - 1)) * (W - pad * 2));
  const y = (c: number) => pad + (1 - Math.max(0, Math.min(1, c))) * (H - pad * 2);
  const path = points.map((p, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(p.confidence).toFixed(1)}`).join(" ");
  const area = `${path} L${x(n - 1).toFixed(1)},${H} L${x(0).toFixed(1)},${H} Z`;
  const first = points[0]?.timestamp;
  const last = points[n - 1]?.timestamp;

  return (
    <div>
      <svg
        className="spark"
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={`Confidence over the last ${n} verifications`}
      >
        <defs>
          <linearGradient id="sparkfill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--brand)" stopOpacity="0.22" />
            <stop offset="100%" stopColor="var(--brand)" stopOpacity="0" />
          </linearGradient>
        </defs>
        <path className="spark-area" d={area} />
        <path className="spark-line" d={path} vectorEffect="non-scaling-stroke" />
        {points.map((p, i) =>
          p.approved ? null : (
            <circle
              key={i}
              className="spark-pt block"
              cx={x(i)}
              cy={y(p.confidence)}
              r={3}
              vectorEffect="non-scaling-stroke"
            />
          ),
        )}
      </svg>
      <div className="bars" aria-hidden="true" style={{ marginTop: 10 }}>
        {points.map((p, i) => (
          <span
            key={i}
            className={p.approved ? "bar pass" : "bar block"}
            style={{ height: `${Math.max(15, Math.round(p.confidence * 100))}%`, opacity: p.approved ? 0.55 : 1 }}
            title={`${p.confidence.toFixed(2)} · ${p.approved ? "approved" : "blocked"}`}
          />
        ))}
      </div>
      {first && last && (
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            marginTop: 8,
            fontFamily: "var(--mono)",
            fontSize: 11,
            color: "var(--fg-4)",
          }}
        >
          <span>{relTime(first)}</span>
          <span>{relTime(last)}</span>
        </div>
      )}
    </div>
  );
}

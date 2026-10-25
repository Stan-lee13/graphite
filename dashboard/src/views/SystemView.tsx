// The Core itself: what /health says about its own durability and what
// /metrics has counted since it started. The counters that mean "page on
// this" sit first, in their own group, because that is the order an
// operator needs them in.

import { api, type Health, type Metrics } from "../api";
import { readBypass } from "../figures";
import { auditReading, persistenceReading } from "../status";
import { usePolling } from "../usePolling";
import { Empty, Fault, FaultNote, Figure, Freshness, PageHead, Section, Skeleton, State, fmt, pollFault, relTime } from "../ui";

interface Counter {
  metric: string;
  label: string;
  /** Non-zero is a problem. */
  alarm?: boolean;
}

const GROUPS: { title: string; note?: string; counters: Counter[] }[] = [
  {
    title: "Bypass signals",
    note: "A non-zero count here means a decision the gate made was not the decision that happened, or the record of it is in doubt.",
    counters: [
      { metric: "graphite_execution_discrepancies_total", label: "Blocked, yet executed on-chain", alarm: true },
      { metric: "graphite_lifecycle_events_on_blocked_total", label: "Signing or submission reported for a blocked transaction", alarm: true },
      { metric: "graphite_execution_chain_bytes_rejected_total", label: "RPC bytes not bound to the signature", alarm: true },
      { metric: "graphite_execution_chain_inconsistent_total", label: "RPC contradicted itself about a signature", alarm: true },
      { metric: "graphite_execution_witness_disagreements_total", label: "Inclusion witness disagreed with the RPC", alarm: true },
      { metric: "graphite_lifecycle_sequence_anomalies_total", label: "Lifecycle reports out of order or contradictory", alarm: true },
    ],
  },
  {
    title: "Verifications",
    counters: [
      { metric: "graphite_verify_requests_total", label: "Requests that reached the handler" },
      { metric: "graphite_verify_approved_total", label: "Approved" },
      { metric: "graphite_verify_blocked_total", label: "Refused" },
      { metric: "graphite_verify_errors_total", label: "Failed before a result", alarm: true },
      { metric: "graphite_execution_checks_total", label: "Execution reconciliations (L8)" },
      { metric: "graphite_lifecycle_events_total", label: "Lifecycle events recorded" },
      { metric: "graphite_lifecycle_events_unverified_total", label: "Lifecycle events with no verification on record", alarm: true },
    ],
  },
  {
    title: "Refused at the door",
    counters: [
      { metric: "graphite_auth_failures_total", label: "Wrong or missing key (401)", alarm: true },
      { metric: "graphite_rate_limited_total", label: "Rate limited (429)" },
      { metric: "graphite_load_shed_total", label: "Shed at the in-flight limit (503)" },
    ],
  },
  {
    title: "Audit trail",
    counters: [
      { metric: "graphite_audit_writes_ok_total", label: "Records appended" },
      { metric: "graphite_audit_writes_failed_total", label: "Appends that failed", alarm: true },
      { metric: "graphite_audit_rotations_ok_total", label: "Rotations completed" },
      { metric: "graphite_audit_rotations_failed_total", label: "Rotations that failed", alarm: true },
    ],
  },
];

export function SystemView() {
  const health = usePolling<Health>(() => api.health(), 5000);
  const metrics = usePolling<Metrics>(() => api.metrics(), 5000);

  // Round 39 (R39-DASH-4): only /health stands in for the whole view. A
  // /metrics that failed before its first answer (a proxy that does not
  // route it, a 404) replaced every /health figure with its fault, so a
  // partial answer showed nothing at all; it now faults the counters only.
  const fault = pollFault(health);
  if (fault) return <Fault error={fault} title="System" />;
  const h = health.data;
  const m = metrics.data;
  const metricsFault = pollFault(metrics);
  const loading = !h;
  const countersLoading = !m && !metricsFault;
  const audit = h ? auditReading(h) : null;
  const persistence = h ? persistenceReading(h) : null;

  // Round 36: the last good /health stays on screen when the Core stops
  // answering (under <Freshness>'s banner), but the Status figure is about
  // now: a Core that is not answering is not "Operational".
  const silent = health.error !== null;

  return (
    <>
      <PageHead title="System" desc="What the Core reports about itself, and what it has counted since it started." />

      <Freshness sources={metricsFault ? [health] : [health, metrics]} />

      <div className="figures five">
        <Figure
          label="Status"
          value={loading ? "—" : silent ? "Not answering" : h.degraded ? "Degraded" : "Operational"}
          tone={loading ? undefined : silent ? "block" : h.degraded ? "warn" : "pass"}
          sub={
            !h
              ? undefined
              : silent && health.updatedAt !== null
                ? `last answered ${relTime(health.updatedAt)}, ${h.degraded ? "degraded" : "operational"}`
                : `${h.service} v${h.version}`
          }
        />
        {/* Round 30: while loading, this said "verdicts are not being
            recorded" — a claim about a Core it had not heard from yet. */}
        {/* Round 39 (R39-DASH-5, status.ts): a /health without these
            fields is "Not reported", not "Off"; failing appends are not
            "Writing". */}
        <Figure label="Audit trail" value={audit?.value ?? "—"} tone={audit?.tone} sub={audit?.sub} />
        <Figure label="Graph snapshots" value={persistence?.value ?? "—"} tone={persistence?.tone} sub={persistence?.sub} />
        {/* Round 30: whether any approval can be executable at all. A Core
            without an RPC simulates nothing, and every approval it makes is
            for analysis only. "Not reported" when the Core does not say. */}
        <Figure
          label="Simulation RPC"
          value={loading ? "—" : h.rpc_attached === undefined ? "Not reported" : h.rpc_attached ? "Attached" : "None"}
          tone={loading ? undefined : h.rpc_attached === true ? "pass" : "warn"}
          sub={loading ? undefined : h.rpc_attached === false ? "no approval is executable" : h.rpc_attached === undefined ? "this Core does not say" : undefined}
        />
        <Figure label="Inclusion witness" value={loading ? "—" : h.inclusion_witness === undefined ? "Not reported" : h.inclusion_witness ? "Configured" : "None"} tone={loading ? undefined : h.inclusion_witness ? "pass" : "idle"} sub={h && h.inclusion_witness === false ? "L8 trusts a single RPC" : undefined} />
        {/* Round 30 (G-08): a witness on the same provider is not a second
            source; "Not reported" when the Core does not say. */}
        <Figure
          label="L8 assurance"
          value={
            loading
              ? "—"
              : h.l8_assurance === undefined
                ? "Not reported"
                : h.l8_assurance.high_assurance
                  ? "High assurance"
                  : h.l8_assurance.witness_independent === true
                    ? "Independent witness"
                    : h.l8_assurance.witness_independent === false
                      ? "Witness not independent"
                      : "Single provider"
          }
          tone={loading ? undefined : h.l8_assurance?.high_assurance || h.l8_assurance?.witness_independent === true ? "pass" : "warn"}
          sub={loading ? undefined : h.l8_assurance?.high_assurance ? "every L8 conclusion needs the witness to agree" : h.l8_assurance === undefined ? "this Core does not say" : "an RPC provider's word, not proof of inclusion"}
        />
        {/* Round 30 (G-07): keyed, the trail is tamper-evident; unkeyed,
            anyone who can write the data directory can rewrite it. */}
        <Figure
          label="Audit integrity"
          value={
            loading
              ? "—"
              : h.audit?.integrity === undefined
                ? "Not reported"
                : h.audit.integrity === "tamper_evident"
                  ? "Tamper-evident"
                  : "Corruption-evident"
          }
          tone={loading ? undefined : h.audit?.integrity === "tamper_evident" && !(h.audit.anchors_failed ?? 0) ? "pass" : "warn"}
          sub={
            loading
              ? undefined
              : (h.audit?.anchors_failed ?? 0) > 0
                ? `${fmt.int(h.audit?.anchors_failed ?? 0)} checkpoint write(s) failed`
                : h.audit?.integrity === "corruption_evident"
                  ? "no MAC key: a coherent rewrite is not detectable"
                  : h.audit?.chain_head_seq != null
                    ? `chain head at record ${fmt.int(h.audit.chain_head_seq)}`
                    : undefined
          }
        />
      </div>

      {!loading && ((h.frozen_baseline_count ?? 0) > 0 || (h.program_upgrades?.detected ?? 0) > 0) && (
        <div className="banner warn" role="status">
          <div>
            {(h.frozen_baseline_count ?? 0) > 0 && (
              <p>
                <strong>{fmt.int(h.frozen_baseline_count ?? 0)} frozen simulation baseline{h.frozen_baseline_count === 1 ? "" : "s"}.</strong>{" "}
                A trusted baseline is refusing clean executions; the authenticated <code translate="no">/api/frozen-baselines</code> names
                the programs, and <code translate="no">graphite evidence promote-shadow</code> is the operator's decision to make.
              </p>
            )}
            {(h.program_upgrades?.detected ?? 0) > 0 && (
              <p>
                <strong>{fmt.int(h.program_upgrades?.detected ?? 0)} program upgrade{h.program_upgrades?.detected === 1 ? "" : "s"} detected</strong>{" "}
                since start{h.program_upgrades?.quarantine_on_upgrade ? "; upgraded programs are quarantined." : "; upgrades do not quarantine (GRAPHITE_QUARANTINE_ON_UPGRADE is off)."}
              </p>
            )}
          </div>
        </div>
      )}

      {h?.degraded && h.degraded_reasons && h.degraded_reasons.length > 0 && (
        <div className="banner warn" role="alert">
          <div>
            <strong>The Core reports itself degraded.</strong>
            <ul>
              {h.degraded_reasons.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {GROUPS.map((g) => (
        <Section
          key={g.title}
          title={g.title}
          meta={
            g.title === "Bypass signals" && metricsFault
              ? <State kind="warn" title="/metrics has not answered">unknown</State>
              : g.title === "Bypass signals" && m
              ? // Round 36: "clear" only when every counter was read and is
                // zero; a counter missing from /metrics is unknown, not 0.
                {
                  alarm: <State kind="block">attention</State>,
                  unknown: (
                    <State kind="warn" title="Not every counter is in the Core's /metrics answer">
                      unknown
                    </State>
                  ),
                  clear: <State kind="pass">clear</State>,
                  unread: undefined,
                }[readBypass(m, g.counters.map((c) => c.metric)).state]
              : undefined
          }
          flush
        >
          {metricsFault && g === GROUPS[0] ? (
            <FaultNote error={metricsFault} />
          ) : metricsFault ? (
            <p className="section-note">Not read: /metrics has not answered.</p>
          ) : countersLoading || !m ? (
            <Skeleton rows={4} cols={2} />
          ) : (
            <table className="data counters">
              <tbody>
                {g.counters.map((c) => {
                  const v = m.get(c.metric);
                  const bad = c.alarm && (v ?? 0) > 0;
                  return (
                    <tr key={c.metric} className={bad ? "flag" : undefined}>
                      <td>
                        {c.label}
                        <span className="row-sub mono" translate="no">
                          {c.metric}
                        </span>
                      </td>
                      <td className={`n ${bad ? "bad" : ""}`}>{v === undefined ? <span className="muted">not exported</span> : fmt.int(v)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
          {g.note && m && <p className="section-note">{g.note}</p>}
        </Section>
      ))}

      {m && m.size === 0 && <Empty title="No metrics" hint="The Core answered /metrics with nothing. That endpoint is where every counter on this page comes from." />}
    </>
  );
}

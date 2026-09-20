// The Core itself: what /health says about its own durability and what
// /metrics has counted since it started. The counters that mean "page on
// this" sit first, in their own group, because that is the order an
// operator needs them in.

import { api, type Health, type Metrics } from "../api";
import { usePolling } from "../usePolling";
import { Empty, Fault, Figure, PageHead, Section, Skeleton, State, fmt } from "../ui";

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

  if (health.error) return <Fault error={health.error} />;
  if (metrics.error) return <Fault error={metrics.error} />;
  const h = health.data;
  const m = metrics.data;
  const loading = !h || !m;

  const alarms = m ? GROUPS.flatMap((g) => g.counters).filter((c) => c.alarm && (m.get(c.metric) ?? 0) > 0) : [];

  return (
    <>
      <PageHead title="System" desc="What the Core reports about itself, and what it has counted since it started." />

      <div className="figures">
        <Figure label="Status" value={loading ? "—" : h.degraded ? "Degraded" : "Operational"} tone={loading ? undefined : h.degraded ? "warn" : "pass"} sub={h ? `${h.service} v${h.version}` : undefined} />
        <Figure label="Audit trail" value={loading ? "—" : h.audit?.enabled ? "Writing" : "Off"} tone={loading ? undefined : h.audit?.enabled ? "pass" : "warn"} sub={h?.audit?.enabled ? `${fmt.bytes(h.audit.active_bytes ?? 0)} active, ${fmt.int(h.audit.archive_count ?? 0)} archived` : "verdicts are not being recorded"} />
        <Figure label="Graph snapshots" value={loading ? "—" : h.graph_persistence?.enabled ? fmt.int(h.graph_persistence.snapshots_ok ?? 0) : "Off"} tone={loading ? undefined : h.graph_persistence?.enabled && !(h.graph_persistence.snapshots_failed ?? 0) ? "pass" : "warn"} sub={h?.graph_persistence?.last_error ?? undefined} />
        <Figure label="Inclusion witness" value={loading ? "—" : h.inclusion_witness ? "Configured" : "None"} tone={loading ? undefined : h.inclusion_witness ? "pass" : "idle"} sub={h && !h.inclusion_witness ? "L8 trusts a single RPC" : undefined} />
      </div>

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
            g.title === "Bypass signals" && m ? (
              alarms.some((a) => g.counters.includes(a)) ? (
                <State kind="block">attention</State>
              ) : (
                <State kind="pass">clear</State>
              )
            ) : undefined
          }
          flush
        >
          {loading ? (
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
          {g.note && !loading && <p className="section-note">{g.note}</p>}
        </Section>
      ))}

      {!loading && m.size === 0 && <Empty title="No metrics" hint="The Core answered /metrics with nothing. That endpoint is where every counter on this page comes from." />}
    </>
  );
}

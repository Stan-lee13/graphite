// What the gate refused, and what it could not even parse. Two different
// populations: a refusal is a verdict with a reason; a rejection never
// reached the pipeline. Both are audited rather than dropped.

import { api } from "../api";
import { refusalTotals, windowLabel } from "../figures";
import { hrefFor } from "../router";
import { useLayout, usePolling } from "../usePolling";
import { CopyId, Empty, Fault, Figure, Freshness, PageHead, Section, Skeleton, State, fmt, pollFault, relTime, shortTime } from "../ui";

/** Rows drawn per table; the rest of the returned window is counted, not drawn. */
const SHOWN = 100;

export function BlockedView() {
  const layout = useLayout();
  const polled = usePolling(() => api.policyViolations(), 5000);
  const fault = pollFault(polled);
  if (fault) return <Fault error={fault} title="Blocked" />;
  const data = polled.data;
  const loading = !data;

  const blocked = [...(data?.violations ?? [])].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
  );
  const rejected = [...(data?.error_violations ?? [])].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
  );
  const byRisk = blocked.filter((v) => v.risk_status === "Blocked").length;
  const latest = blocked[0]?.timestamp ?? rejected[0]?.timestamp;
  // Round 29 (audit 2026-10-20, D1): the Core returns its newest 200 of each
  // list. The totals are the server's; the risk/policy split is over what
  // came back, and says so.
  const totals = data ? refusalTotals(data) : { refused: 0, rejected: 0, rejectedAtLeast: false };
  const refusedWin = windowLabel(blocked.length, totals.refused);
  const shownOf = (shown: number, total: number, atLeast = false) =>
    shown < total || atLeast ? `newest ${fmt.int(shown)} of ${atLeast ? "≥ " : ""}${fmt.int(total)}` : fmt.int(total);

  return (
    <>
      <PageHead title="Blocked" desc="Transactions the gate refused, and requests it could not read." />

      <Freshness sources={[polled]} />

      <div className="figures">
        <Figure
          label="Refused"
          value={loading ? "—" : fmt.int(totals.refused)}
          tone={totals.refused > 0 ? "block" : "idle"}
          sub={loading ? undefined : `${refusedWin}: ${byRisk} on risk, ${blocked.length - byRisk} on policy`}
        />
        <Figure
          label="Rejected"
          value={loading ? "—" : `${totals.rejectedAtLeast ? "≥ " : ""}${fmt.int(totals.rejected)}`}
          tone={totals.rejected > 0 ? "warn" : "idle"}
          sub="malformed or oversized"
        />
        <Figure label="Most recent" value={loading ? "—" : latest ? relTime(latest) : "none"} tone={latest ? undefined : "idle"} />
      </div>

      <Section
        title="Refused transactions"
        meta={loading ? undefined : shownOf(Math.min(SHOWN, blocked.length), totals.refused)}
        flush
      >
        {loading ? (
          <Skeleton rows={5} cols={6} />
        ) : blocked.length === 0 ? (
          <Empty title="Nothing refused" hint="Every verification so far met its policy floor and raised no risk finding." />
        ) : layout === "phone" ? (
          <ul className="rows">
            {blocked.slice(0, SHOWN).map((v) => (
              <li key={v.audit_trail_id} className="row">
                <a className="row-main" href={hrefFor("programs", v.program_id)}>
                  <span className="row-title">
                    {v.protocol_name} <span className="row-sub">{v.instruction_name}</span>
                  </span>
                  <span className="row-meta">
                    <span>{relTime(v.timestamp)}</span>
                    <CopyId value={v.audit_trail_id} />
                  </span>
                </a>
                <div className="row-side">
                  <span className="num muted">{fmt.score(v.confidence)}</span>
                  {v.risk_status === "Blocked" ? <State kind="block">risk</State> : <State kind="warn">policy</State>}
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <table className="data">
            <thead>
              <tr>
                <th>Time</th>
                <th>Program</th>
                <th>Instruction</th>
                <th className="n">Confidence</th>
                <th>Policy</th>
                <th>Risk</th>
                <th>Audit ID</th>
              </tr>
            </thead>
            <tbody>
              {blocked.slice(0, SHOWN).map((v) => (
                <tr key={v.audit_trail_id}>
                  <td className="t" title={v.timestamp}>
                    {shortTime(v.timestamp)}
                  </td>
                  <td>
                    <a className="cell-link" href={hrefFor("programs", v.program_id)}>
                      {v.protocol_name}
                    </a>
                  </td>
                  <td>{v.instruction_name}</td>
                  <td className="n">{fmt.score(v.confidence)}</td>
                  <td>
                    <State kind={v.policy_verdict === "Approved" ? "pass" : "warn"}>{v.policy_verdict}</State>
                  </td>
                  <td>
                    <State kind={v.risk_status === "Clear" ? "pass" : "block"}>{v.risk_status}</State>
                  </td>
                  <td className="id">
                    <CopyId value={v.audit_trail_id} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      <Section
        title="Rejected requests"
        meta={loading ? undefined : shownOf(Math.min(SHOWN, rejected.length), totals.rejected, totals.rejectedAtLeast)}
        flush
      >
        {loading ? (
          <Skeleton rows={3} cols={4} />
        ) : rejected.length === 0 ? (
          <Empty title="No rejected requests" hint="Malformed payloads, oversized bodies and probes would appear here. They are audited, never silently dropped." />
        ) : layout === "phone" ? (
          <ul className="rows">
            {rejected.slice(0, SHOWN).map((e, i) => (
              <li key={`${e.timestamp}-${i}`} className="row">
                <div className="row-main">
                  <span className="row-title">
                    {e.error_type} <span className="row-sub num">{e.status}</span>
                  </span>
                  <span className="row-meta">
                    <span>{relTime(e.timestamp)}</span>
                    <span className="clamp">{e.error}</span>
                  </span>
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <table className="data">
            <thead>
              <tr>
                <th>Time</th>
                <th>Program</th>
                <th>Instruction</th>
                <th className="n">Status</th>
                <th>Type</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {rejected.slice(0, SHOWN).map((e, i) => (
                <tr key={`${e.timestamp}-${i}`}>
                  <td className="t" title={e.timestamp}>
                    {shortTime(e.timestamp)}
                  </td>
                  <td className="id">{e.program_id ? <CopyId value={e.program_id} /> : <span className="muted">—</span>}</td>
                  <td className="id">{e.instruction_name || <span className="muted">—</span>}</td>
                  <td className="n">{e.status}</td>
                  <td>{e.error_type}</td>
                  <td className="wrap muted">{e.error}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>
    </>
  );
}

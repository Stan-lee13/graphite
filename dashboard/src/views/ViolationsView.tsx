import { usePolling } from "../usePolling";
import { api } from "../api";
import {
  CopyId,
  Empty,
  ErrorState,
  Metric,
  Panel,
  State,
  TableSkeleton,
  ViewHead,
  relTime,
  shortTime,
} from "../ui";

export function ViolationsView() {
  const { data, error } = usePolling(() => api.policyViolations(), 5000);

  if (error) return <ErrorState message={error} />;
  const loading = !data;

  const blocked = data?.violations ?? [];
  const rejected = data?.error_violations ?? [];
  const latest = blocked[0]?.timestamp ?? rejected[0]?.timestamp;

  return (
    <>
      <ViewHead
        title="Blocked"
        note="transactions the gate refused, and requests it could not parse"
      >
        <Metric
          label="Blocked"
          value={loading ? "—" : blocked.length}
          tone={blocked.length > 0 ? "block" : "idle"}
          sub="failed verification"
        />
        <Metric
          label="Rejected"
          value={loading ? "—" : rejected.length}
          tone={rejected.length > 0 ? "warn" : "idle"}
          sub="malformed or oversized"
        />
        <Metric
          label="Most recent"
          value={loading ? "—" : latest ? relTime(latest) : "none"}
          tone={latest ? undefined : "idle"}
        />
      </ViewHead>

      <div className="body">
        <Panel title="Blocked transactions" meta={loading ? "" : `${blocked.length}`} flush>
          {loading ? (
            <TableSkeleton rows={5} cols={6} />
          ) : blocked.length === 0 ? (
            <Empty
              title="Nothing blocked"
              hint="Every verification so far met its policy threshold and raised no risk finding."
            />
          ) : (
            <table className="data">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Protocol</th>
                  <th>Instruction</th>
                  <th>Program</th>
                  <th className="n">Confidence</th>
                  <th>Policy</th>
                  <th>Risk</th>
                  <th>Audit ID</th>
                </tr>
              </thead>
              <tbody>
                {blocked.slice(0, 100).map((v) => (
                  <tr key={v.audit_trail_id}>
                    <td className="t" title={v.timestamp}>
                      {shortTime(v.timestamp)}
                    </td>
                    <td className="primary">{v.protocol_name}</td>
                    <td>{v.instruction_name}</td>
                    <td className="id">
                      <CopyId value={v.program_id} />
                    </td>
                    <td className="n">{v.confidence.toFixed(2)}</td>
                    <td>
                      <State kind={v.policy_verdict === "Approved" ? "pass" : "block"}>
                        {v.policy_verdict}
                      </State>
                    </td>
                    <td>
                      <State kind={v.risk_status === "Clear" ? "pass" : "block"}>
                        {v.risk_status}
                      </State>
                    </td>
                    <td className="id">
                      <CopyId value={v.audit_trail_id} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>

        <Panel
          title="Rejected requests"
          meta={loading ? "" : `${rejected.length}`}
          flush
        >
          {loading ? (
            <TableSkeleton rows={3} cols={4} />
          ) : rejected.length === 0 ? (
            <Empty
              title="No rejected requests"
              hint="Malformed payloads, oversized bodies and probing attempts would appear here — they are audited rather than silently dropped."
            />
          ) : (
            <table className="data">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Program</th>
                  <th>Instruction</th>
                  <th className="n">Status</th>
                  <th>Type</th>
                  <th>Error</th>
                </tr>
              </thead>
              <tbody>
                {rejected.slice(0, 100).map((e, i) => (
                  <tr key={`${e.timestamp}-${i}`}>
                    <td className="t" title={e.timestamp}>
                      {shortTime(e.timestamp)}
                    </td>
                    <td className="id">
                      <CopyId value={e.program_id} />
                    </td>
                    <td className="id">{e.instruction_name}</td>
                    <td className="n">{e.status}</td>
                    <td>{e.error_type}</td>
                    <td style={{ color: "var(--ink-2)" }}>{e.error}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      </div>
    </>
  );
}

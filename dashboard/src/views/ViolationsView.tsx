import { usePolling } from "../usePolling";
import { api } from "../api";
import { ErrorState, Loading, shortId } from "../ui";

export function ViolationsView() {
  const { data, error, loading } = usePolling(() => api.policyViolations(), 5000);

  if (error) return <ErrorState message={error} />;
  if (loading || !data) return <Loading what="policy violations" />;

  return (
    <section>
      <div className="view-head">
        <h2>Policy Violations</h2>
        <span className="muted">
          {data.count} total · {data.violations.length} blocked verifications ·{" "}
          {data.error_violations.length} rejected requests
        </span>
      </div>

      <div className="card">
        <h3>Blocked transactions</h3>
        {data.violations.length === 0 ? (
          <p className="muted">No blocked transactions recorded.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Protocol</th>
                <th>Program</th>
                <th>Confidence</th>
                <th>Policy verdict</th>
                <th>Risk status</th>
              </tr>
            </thead>
            <tbody>
              {data.violations.slice(0, 100).map((v) => (
                <tr key={v.audit_trail_id}>
                  <td>{new Date(v.timestamp).toLocaleString()}</td>
                  <td>{v.protocol_name}</td>
                  <td className="mono" title={v.program_id}>{shortId(v.program_id, 8, 5)}</td>
                  <td>{v.confidence.toFixed(3)}</td>
                  <td><span className="pill block">{v.policy_verdict}</span></td>
                  <td>{v.risk_status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card">
        <h3>Rejected requests (error path)</h3>
        {data.error_violations.length === 0 ? (
          <p className="muted">No rejected requests recorded.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Program</th>
                <th>Error type</th>
                <th>Status</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {data.error_violations.slice(0, 100).map((v, i) => (
                <tr key={i}>
                  <td>{new Date(v.timestamp).toLocaleString()}</td>
                  <td className="mono">{shortId(v.program_id, 8, 5)}</td>
                  <td className="mono">{v.error_type}</td>
                  <td>{v.status}</td>
                  <td className="small">{v.error}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}

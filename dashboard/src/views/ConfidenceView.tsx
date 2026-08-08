import { usePolling } from "../usePolling";
import { api } from "../api";
import { ErrorState, Loading, shortId } from "../ui";

const W = 960;
const H = 300;
const PAD = 40;

export function ConfidenceView() {
  const { data, error, loading } = usePolling(() => api.confidenceHistory(), 5000);

  if (error) return <ErrorState message={error} />;
  if (loading || !data) return <Loading what="confidence history" />;

  const pts = data.series;
  if (pts.length === 0) {
    return (
      <section>
        <div className="view-head">
          <h2>Confidence History</h2>
        </div>
        <div className="card">
          <p className="muted">
            No verifications yet. Submit a transaction to /verify and the audit
            trail will feed this series.
          </p>
        </div>
      </section>
    );
  }

  const minT = Math.min(...pts.map((p) => new Date(p.timestamp).getTime()));
  const maxT = Math.max(...pts.map((p) => new Date(p.timestamp).getTime()));
  const tSpan = Math.max(maxT - minT, 1);
  const x = (t: number) => PAD + ((t - minT) / tSpan) * (W - 2 * PAD);
  const y = (c: number) => H - PAD - Math.min(Math.max(c, 0), 1) * (H - 2 * PAD);

  const line = pts.map((p, i) => `${i === 0 ? "M" : "L"}${x(new Date(p.timestamp).getTime()).toFixed(1)},${y(p.confidence).toFixed(1)}`).join(" ");
  const maxConf = Math.max(...pts.map((p) => p.confidence));

  return (
    <section>
      <div className="view-head">
        <h2>Confidence History</h2>
        <span className="muted">
          {pts.length} verifications · peak {maxConf.toFixed(3)} · green = approved, red = blocked
        </span>
      </div>
      <div className="card">
        <svg viewBox={`0 0 ${W} ${H}`} className="chart-svg" role="img" aria-label="Confidence over time">
          <line x1={PAD} y1={H - PAD} x2={W - PAD} y2={H - PAD} className="axis" />
          <line x1={PAD} y1={PAD} x2={PAD} y2={H - PAD} className="axis" />
          {[0, 0.25, 0.5, 0.75, 1.0].map((g) => (
            <g key={g}>
              <line x1={PAD} y1={y(g)} x2={W - PAD} y2={y(g)} className="gridline" />
              <text x={PAD - 8} y={y(g) + 4} textAnchor="end" className="axis-label">
                {g.toFixed(2)}
              </text>
            </g>
          ))}
          <polyline points={line} fill="none" className="line-smooth" />
          {pts.map((p, i) => (
            <circle
              key={i}
              cx={x(new Date(p.timestamp).getTime())}
              cy={y(p.confidence)}
              r={3.5}
              className={p.approved ? "dot ok" : "dot block"}
            >
              <title>{`${p.program_id} ${shortId(p.program_id, 6, 4)} conf=${p.confidence.toFixed(3)} ${p.approved ? "approved" : "blocked"}`}</title>
            </circle>
          ))}
        </svg>
        <table className="table compact">
          <thead>
            <tr>
              <th>Time</th>
              <th>Program</th>
              <th>Confidence</th>
              <th>Outcome</th>
              <th>Audit trail</th>
            </tr>
          </thead>
          <tbody>
            {pts.slice(-12).reverse().map((p) => (
              <tr key={p.audit_trail_id}>
                <td>{new Date(p.timestamp).toLocaleString()}</td>
                <td className="mono">{shortId(p.program_id, 8, 5)}</td>
                <td>{p.confidence.toFixed(3)}</td>
                <td>{p.approved ? <span className="pill ok">approved</span> : <span className="pill block">blocked</span>}</td>
                <td className="mono small">{shortId(p.audit_trail_id, 10, 6)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

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
  shortTime,
} from "../ui";

const W = 1040;
const H = 260;
const PAD_L = 34;
const PAD_R = 12;
const PAD_T = 14;
const PAD_B = 26;

export function ConfidenceView() {
  const { data, error } = usePolling(() => api.confidenceHistory(), 5000);

  if (error) return <ErrorState message={error} />;
  const loading = !data;
  const pts = data?.series ?? [];

  const approved = pts.filter((p) => p.approved).length;
  const mean = pts.length
    ? pts.reduce((s, p) => s + p.confidence, 0) / pts.length
    : 0;

  return (
    <>
      <ViewHead
        title="Confidence"
        note="every verification, in the order the audit trail recorded it"
      >
        <Metric label="Verifications" value={loading ? "—" : data.count} />
        <Metric
          label="Approved"
          value={loading ? "—" : approved}
          tone={pts.length && approved === 0 ? "idle" : "pass"}
          sub={pts.length ? `${Math.round((approved / pts.length) * 100)}%` : undefined}
        />
        <Metric
          label="Blocked"
          value={loading ? "—" : pts.length - approved}
          tone={pts.length - approved > 0 ? "block" : "idle"}
        />
        <Metric
          label="Mean confidence"
          value={loading ? "—" : mean.toFixed(2)}
          sub="across the window"
        />
      </ViewHead>

      <div className="body">
        <Panel
          title="Confidence over time"
          meta={pts.length ? `${pts.length} points` : ""}
        >
          {loading ? (
            <div style={{ height: H }}>
              <TableSkeleton rows={1} cols={1} />
            </div>
          ) : pts.length === 0 ? (
            <Empty
              title="No verifications recorded yet"
              hint="Post a transaction to /verify and each result lands here as it is written to the audit trail."
            />
          ) : (
            <Chart pts={pts} />
          )}
        </Panel>

        {!loading && pts.length > 0 && (
          <Panel title="Recent verifications" meta={`latest ${Math.min(pts.length, 50)}`} flush>
            <table className="data">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Program</th>
                  <th className="n">Confidence</th>
                  <th>Outcome</th>
                  <th>Audit ID</th>
                </tr>
              </thead>
              <tbody>
                {[...pts]
                  .reverse()
                  .slice(0, 50)
                  .map((p) => (
                    <tr key={p.audit_trail_id}>
                      <td className="t" title={p.timestamp}>
                        {shortTime(p.timestamp)}
                      </td>
                      <td className="id">
                        <CopyId value={p.program_id} />
                      </td>
                      <td className="n">{p.confidence.toFixed(2)}</td>
                      <td>
                        <State kind={p.approved ? "pass" : "block"}>
                          {p.approved ? "approved" : "blocked"}
                        </State>
                      </td>
                      <td className="id">
                        <CopyId value={p.audit_trail_id} />
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </Panel>
        )}
      </div>
    </>
  );
}

function Chart({
  pts,
}: {
  pts: { timestamp: string; confidence: number; approved: boolean }[];
}) {
  const times = pts.map((p) => new Date(p.timestamp).getTime());
  const minT = Math.min(...times);
  const maxT = Math.max(...times);
  const span = Math.max(maxT - minT, 1);

  const x = (t: number) => PAD_L + ((t - minT) / span) * (W - PAD_L - PAD_R);
  const y = (c: number) =>
    H - PAD_B - Math.min(Math.max(c, 0), 1) * (H - PAD_T - PAD_B);

  const line = pts
    .map((p, i) => `${i === 0 ? "M" : "L"}${x(times[i]).toFixed(1)},${y(p.confidence).toFixed(1)}`)
    .join(" ");

  // Fill under the line, closed along the baseline.
  const area =
    `${line} L${x(times[times.length - 1]).toFixed(1)},${(H - PAD_B).toFixed(1)}` +
    ` L${x(times[0]).toFixed(1)},${(H - PAD_B).toFixed(1)} Z`;

  // The wallet-profile thresholds a reader is implicitly comparing against.
  // Drawing them turns "0.44" from a bare number into "below the Gaming bar".
  const thresholds = [
    { at: 0.55, label: "gaming" },
    { at: 0.8, label: "trading" },
    { at: 0.95, label: "treasury" },
  ];

  return (
    <svg
      className="chart"
      viewBox={`0 0 ${W} ${H}`}
      role="img"
      aria-label="Confidence score over time"
    >
      {[0, 0.25, 0.5, 0.75, 1].map((v) => (
        <g key={v}>
          <line className="grid" x1={PAD_L} x2={W - PAD_R} y1={y(v)} y2={y(v)} />
          <text className="axis-label" x={4} y={y(v) + 3.5}>
            {v.toFixed(2)}
          </text>
        </g>
      ))}

      {thresholds.map((t) => (
        <g key={t.label}>
          <line className="threshold" x1={PAD_L} x2={W - PAD_R} y1={y(t.at)} y2={y(t.at)} />
          <text className="axis-label" x={W - PAD_R} y={y(t.at) - 4} textAnchor="end">
            {t.label} {t.at}
          </text>
        </g>
      ))}

      <path className="series-area" d={area} />
      <path className="series" d={line} />

      {pts.map((p, i) => (
        <circle
          key={i}
          className={p.approved ? "pt pass" : "pt block"}
          cx={x(times[i])}
          cy={y(p.confidence)}
          r={2.5}
        >
          <title>
            {`${p.confidence.toFixed(3)} — ${p.approved ? "approved" : "blocked"}\n${p.timestamp}`}
          </title>
        </circle>
      ))}

      <line className="axis" x1={PAD_L} x2={W - PAD_R} y1={H - PAD_B} y2={H - PAD_B} />
      <text className="axis-label" x={PAD_L} y={H - 8}>
        {shortTime(pts[0].timestamp)}
      </text>
      <text className="axis-label" x={W - PAD_R} y={H - 8} textAnchor="end">
        {shortTime(pts[pts.length - 1].timestamp)}
      </text>
    </svg>
  );
}

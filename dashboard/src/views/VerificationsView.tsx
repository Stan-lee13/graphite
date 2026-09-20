// Every verification the trail recorded, in order, with its confidence
// drawn against the three wallet-profile floors. "0.44" is a bare number;
// "0.44, under the Gaming floor" is a reason.

import { useState } from "react";
import { api, type ConfidencePoint } from "../api";
import { hrefFor } from "../router";
import { useLayout, usePolling } from "../usePolling";
import { CopyId, Empty, Fault, Figure, PageHead, Section, Skeleton, State, fmt, relTime, shortTime } from "../ui";

const W = 1040;
const H = 240;
const PAD_L = 36;
const PAD_R = 12;
const PAD_T = 12;
const PAD_B = 24;

/** The wallet-profile floors a reader is implicitly comparing against. */
const FLOORS = [
  { at: 0.55, label: "Gaming" },
  { at: 0.8, label: "Trading" },
  { at: 0.95, label: "Treasury" },
];

type Filter = "all" | "approved" | "refused";

export function VerificationsView() {
  const layout = useLayout();
  const { data, error } = usePolling(() => api.confidenceHistory(), 5000);
  const graph = usePolling(() => api.graph(), 30000);
  const [filter, setFilter] = useState<Filter>("all");

  if (error) return <Fault error={error} />;
  const loading = !data;
  const pts = data?.series ?? [];
  const nameOf = new Map((graph.data?.nodes ?? []).map((n) => [n.program_id, n.name]));

  const approved = pts.filter((p) => p.approved).length;
  const mean = pts.length ? pts.reduce((s, p) => s + p.confidence, 0) / pts.length : 0;

  const listed = [...pts]
    .reverse()
    .filter((p) => (filter === "all" ? true : filter === "approved" ? p.approved : !p.approved))
    .slice(0, 100);

  return (
    <>
      <PageHead title="Verifications" desc="Every verdict in the order the audit trail recorded it." />

      <div className="figures">
        <Figure label="On record" value={loading ? "—" : fmt.int(data.count)} />
        <Figure label="Approved" value={loading ? "—" : fmt.int(approved)} sub={pts.length ? fmt.pct(approved / pts.length) : undefined} tone="pass" />
        <Figure label="Refused" value={loading ? "—" : fmt.int(pts.length - approved)} tone={pts.length - approved > 0 ? "block" : "idle"} />
        <Figure label="Mean confidence" value={loading ? "—" : fmt.score(mean)} sub="across the window" />
      </div>

      <Section title="Confidence" meta={pts.length ? `${fmt.int(pts.length)} points, floors drawn for each wallet profile` : undefined}>
        {loading ? (
          <Skeleton rows={2} cols={1} />
        ) : pts.length === 0 ? (
          <Empty title="No verifications yet" hint="Post a transaction to /verify and each result lands here as the trail records it." />
        ) : (
          <Chart pts={pts} compact={layout === "phone"} />
        )}
      </Section>

      {!loading && pts.length > 0 && (
        <Section
          title="Recent"
          meta={
            <div className="seg" role="radiogroup" aria-label="Show">
              {(["all", "approved", "refused"] as Filter[]).map((f) => (
                <button key={f} type="button" role="radio" aria-checked={filter === f} className={filter === f ? "on" : undefined} onClick={() => setFilter(f)}>
                  {f === "all" ? "All" : f === "approved" ? "Approved" : "Refused"}
                </button>
              ))}
            </div>
          }
          flush
        >
          {listed.length === 0 ? (
            <Empty title={filter === "approved" ? "Nothing approved" : "Nothing refused"} />
          ) : layout === "phone" ? (
            <ul className="rows">
              {listed.map((p) => (
                <li key={p.audit_trail_id} className="row">
                  <a className="row-main" href={hrefFor("programs", p.program_id)}>
                    <span className="row-title">{nameOf.get(p.program_id) ?? p.program_id.slice(0, 10) + "…"}</span>
                    <span className="row-meta">
                      <span>{relTime(p.timestamp)}</span>
                      <CopyId value={p.audit_trail_id} />
                    </span>
                  </a>
                  <div className="row-side">
                    <span className="num muted">{fmt.score(p.confidence)}</span>
                    {p.approved ? <State kind="pass">approved</State> : <State kind="block">refused</State>}
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
                  <th className="n">Confidence</th>
                  <th>Verdict</th>
                  <th>Audit ID</th>
                </tr>
              </thead>
              <tbody>
                {listed.map((p) => (
                  <tr key={p.audit_trail_id}>
                    <td className="t" title={p.timestamp}>
                      {shortTime(p.timestamp)}
                    </td>
                    <td>
                      <a className="cell-link" href={hrefFor("programs", p.program_id)}>
                        {nameOf.get(p.program_id) ?? <CopyId value={p.program_id} />}
                      </a>
                    </td>
                    <td className="n">{fmt.score(p.confidence)}</td>
                    <td>{p.approved ? <State kind="pass">approved</State> : <State kind="block">refused</State>}</td>
                    <td className="id">
                      <CopyId value={p.audit_trail_id} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Section>
      )}
    </>
  );
}

function Chart({ pts, compact }: { pts: ConfidencePoint[]; compact: boolean }) {
  const times = pts.map((p) => new Date(p.timestamp).getTime());
  const minT = Math.min(...times);
  const maxT = Math.max(...times);
  const span = Math.max(maxT - minT, 1);
  const h = compact ? 180 : H;

  const x = (t: number) => PAD_L + ((t - minT) / span) * (W - PAD_L - PAD_R);
  const y = (c: number) => h - PAD_B - Math.min(Math.max(c, 0), 1) * (h - PAD_T - PAD_B);

  const line = pts.map((p, i) => `${i === 0 ? "M" : "L"}${x(times[i]).toFixed(1)},${y(p.confidence).toFixed(1)}`).join(" ");
  const area = `${line} L${x(times[times.length - 1]).toFixed(1)},${(h - PAD_B).toFixed(1)} L${x(times[0]).toFixed(1)},${(h - PAD_B).toFixed(1)} Z`;

  return (
    <svg className="chart" viewBox={`0 0 ${W} ${h}`} role="img" aria-label="Confidence over time, with the Gaming, Trading and Treasury floors">
      {[0, 0.25, 0.5, 0.75, 1].map((v) => (
        <g key={v}>
          <line className="grid" x1={PAD_L} x2={W - PAD_R} y1={y(v)} y2={y(v)} />
          <text className="axis-label" x={4} y={y(v) + 3.5}>
            {v.toFixed(2)}
          </text>
        </g>
      ))}
      {FLOORS.map((f) => (
        <g key={f.label}>
          <line className="floor" x1={PAD_L} x2={W - PAD_R} y1={y(f.at)} y2={y(f.at)} />
          <text className="axis-label floor-label" x={W - PAD_R} y={y(f.at) - 4} textAnchor="end">
            {f.label} {f.at}
          </text>
        </g>
      ))}
      <path className="series-area" d={area} />
      <path className="series" d={line} />
      {pts.map((p, i) => (
        <circle key={p.audit_trail_id} className={p.approved ? "pt pass" : "pt block"} cx={x(times[i])} cy={y(p.confidence)} r={p.approved ? 2 : 3}>
          <title>{`${fmt.score(p.confidence)}, ${p.approved ? "approved" : "refused"}\n${shortTime(p.timestamp)}`}</title>
        </circle>
      ))}
      <line className="axis" x1={PAD_L} x2={W - PAD_R} y1={h - PAD_B} y2={h - PAD_B} />
      <text className="axis-label" x={PAD_L} y={h - 8}>
        {shortTime(pts[0].timestamp)}
      </text>
      <text className="axis-label" x={W - PAD_R} y={h - 8} textAnchor="end">
        {shortTime(pts[pts.length - 1].timestamp)}
      </text>
    </svg>
  );
}

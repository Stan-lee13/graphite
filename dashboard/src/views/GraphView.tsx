import { useMemo, useState } from "react";
import { usePolling } from "../usePolling";
import { api, type GraphNode } from "../api";
import { ErrorState, Loading, TierBadge, shortId } from "../ui";

const W = 960;
const H = 620;

/** Deterministic circular-ish layout keyed by program id (P2 — same graph,
 *  same picture). CPI edges that point at an unlisted target get a stub node. */
function layout(nodes: GraphNode[], edges: { from: string; to: string }[]) {
  const index = new Map(nodes.map((n, i) => [n.program_id, i]));
  const targets = new Set(edges.map((e) => e.to));
  const extra: GraphNode[] = [...targets]
    .filter((t) => !index.has(t))
    .map((t) => ({
      program_id: t,
      name: shortId(t, 8, 5),
      manifest_version: null,
      trust_tier: "Unknown",
      instruction_count: 0,
      baseline_samples: null,
      battle_tested_tx_count: 0,
      community_verified_count: 0,
      quarantined: false,
      quarantine_reason: null,
      cpi_targets: [],
    }));
  const all = [...nodes, ...extra];
  const cx = W / 2;
  const cy = H / 2;
  const radius = Math.min(cx, cy) - 90;
  const pos = all.map((_, i) => {
    const angle = (i / all.length) * Math.PI * 2 - Math.PI / 2;
    return { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) };
  });
  return { all, pos, index: new Map(all.map((n, i) => [n.program_id, i])) };
}

export function GraphView() {
  const { data, error, loading } = usePolling(() => api.graph(), 5000);
  const [selected, setSelected] = useState<string | null>(null);

  const { all, pos, index } = useMemo(
    () => (data ? layout(data.nodes, data.edges) : { all: [], pos: [], index: new Map() }),
    [data],
  );

  if (error) return <ErrorState message={error} />;
  if (loading || !data) return <Loading what="semantic graph" />;

  const selectedNode = all.find((n) => n.program_id === selected) ?? null;

  return (
    <section>
      <div className="view-head">
        <h2>Semantic Graph</h2>
        <span className="muted">
          {all.length} nodes · {data.edges.length} directed CPI edges (read-only)
        </span>
      </div>
      <div className="card graph-card">
        <svg viewBox={`0 0 ${W} ${H}`} className="graph-svg" role="img" aria-label="CPI graph">
          {data.edges.map((e, i) => {
            const a = index.get(e.from);
            const b = index.get(e.to);
            if (a === undefined || b === undefined) return null;
            return (
              <line
                key={i}
                x1={pos[a].x}
                y1={pos[a].y}
                x2={pos[b].x}
                y2={pos[b].y}
                className={selected === e.from || selected === e.to ? "edge active" : "edge"}
              />
            );
          })}
          {all.map((n, i) => (
            <g
              key={n.program_id}
              transform={`translate(${pos[i].x}, ${pos[i].y})`}
              className={`node-g ${selected === n.program_id ? "active" : ""}`}
              onClick={() => setSelected(n.program_id)}
              role="button"
              tabIndex={0}
              onKeyDown={(ev) => {
                if (ev.key === "Enter") setSelected(n.program_id);
              }}
            >
              <circle
                r={n.battle_tested_tx_count > 0 ? 18 : 12}
                className={
                  n.quarantined
                    ? "node-circle quarantined"
                    : n.battle_tested_tx_count > 0
                      ? "node-circle hot"
                      : "node-circle"
                }
              />
              <title>{`${n.name} (${n.program_id}) · ${n.trust_tier}`}</title>
              <text y={34} textAnchor="middle" className="node-label">
                {n.name.length > 18 ? `${n.name.slice(0, 17)}…` : n.name}
              </text>
            </g>
          ))}
        </svg>
        <div className="graph-side">
          {selectedNode ? (
            <div className="card inset">
              <h3>{selectedNode.name}</h3>
              <p className="mono">{selectedNode.program_id}</p>
              <p><TierBadge tier={selectedNode.trust_tier} /></p>
              <dl className="kv">
                <dt>Instructions</dt>
                <dd>{selectedNode.instruction_count}</dd>
                <dt>Baseline samples</dt>
                <dd>{selectedNode.baseline_samples ?? "—"}</dd>
                <dt>Battle-tested tx</dt>
                <dd>{selectedNode.battle_tested_tx_count.toLocaleString()}</dd>
                <dt>Community verified</dt>
                <dd>{selectedNode.community_verified_count}</dd>
              </dl>
              {selectedNode.cpi_targets.length > 0 && (
                <div>
                  <h4>CPI targets</h4>
                  <ul className="cpi-list">
                    {selectedNode.cpi_targets.map((t) => (
                      <li key={t} className="mono">{shortId(t, 8, 5)}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ) : (
            <div className="card inset muted">
              Click a node to inspect its earned evidence, quarantine state, and
              CPI targets. Edge = program may invoke the target via CPI.
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

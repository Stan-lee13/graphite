// The declared CPI relation, drawn in call order.
//
// A CPI graph is not a social network — it is a call relation, and on Solana
// that relation is overwhelmingly one-directional: many protocol programs fan
// into a handful of system-level programs. A ring forces the eye to trace a
// chord across the middle to answer "who calls the Token Program" and packs
// thirty labels into a band where they collide. So on a wide screen it is
// columns by role, left to right in call order, every label horizontal. On a
// phone the same roles are three lists: the picture would not survive the
// width, and a list answers the same question.

import { useMemo } from "react";
import { api, type GraphEdge, type GraphNode } from "../api";
import { hrefFor, navigate } from "../router";
import { useLayout, usePolling } from "../usePolling";
import { CopyId, Detail, Empty, Fault, Figure, PageHead, Section, Skeleton, State, TierBadge, fmt, shortId } from "../ui";
import { ProgramDetail } from "./ProgramsView";

const W = 1000;
const PAD_T = 34;
const PAD_B = 20;
const X_FIRST = 208;
const X_LAST = 782;
const ROW = 30;
const LABEL_W = 205;

type Role = "caller" | "both" | "target" | "isolated";

interface Placed {
  node: GraphNode;
  role: Role;
  col: number;
  x: number;
  y: number;
  fanIn: number;
  fanOut: number;
}

const COLUMN_TITLES: Record<Exclude<Role, "isolated">, string> = {
  caller: "Invokes",
  both: "Invokes and is invoked",
  target: "Is invoked",
};

function layout(nodes: GraphNode[], edges: GraphEdge[]) {
  const known = new Set(nodes.map((n) => n.program_id));

  // A CPI target with no manifest of its own still belongs on the picture: an
  // undeclared callee is exactly the thing an operator needs to see.
  const stubs: GraphNode[] = [...new Set(edges.map((e) => e.to))]
    .filter((t) => !known.has(t))
    .map((t) => ({
      program_id: t,
      name: shortId(t, 6, 4),
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

  const all = [...nodes, ...stubs];
  const fanIn = new Map<string, number>();
  const fanOut = new Map<string, number>();
  for (const e of edges) {
    fanOut.set(e.from, (fanOut.get(e.from) ?? 0) + 1);
    fanIn.set(e.to, (fanIn.get(e.to) ?? 0) + 1);
  }
  const roleOf = (id: string): Role => {
    const i = fanIn.get(id) ?? 0;
    const o = fanOut.get(id) ?? 0;
    if (i === 0 && o === 0) return "isolated";
    if (i === 0) return "caller";
    if (o === 0) return "target";
    return "both";
  };
  const degree = (n: GraphNode) => (fanIn.get(n.program_id) ?? 0) + (fanOut.get(n.program_id) ?? 0);

  const isolated = all.filter((n) => roleOf(n.program_id) === "isolated");
  const columns = (["caller", "both", "target"] as const)
    .map((role) => ({
      role,
      members: all.filter((n) => roleOf(n.program_id) === role).sort((a, b) => degree(b) - degree(a)),
    }))
    .filter((c) => c.members.length > 0);

  const tallest = columns.reduce((m, c) => Math.max(m, c.members.length), 1);
  const H = Math.max(PAD_T + PAD_B + (tallest - 1) * ROW + 20, 320);
  const top = PAD_T + 10;
  const bottom = H - PAD_B;

  const placed = new Map<string, Placed>();
  columns.forEach((col, ci) => {
    const x = columns.length === 1 ? (X_FIRST + X_LAST) / 2 : X_FIRST + (ci / (columns.length - 1)) * (X_LAST - X_FIRST);
    const span = (col.members.length - 1) * ROW;
    const y0 = (top + bottom) / 2 - span / 2;
    col.members.forEach((node, i) => {
      placed.set(node.program_id, {
        node,
        role: col.role,
        col: ci,
        x,
        y: y0 + i * ROW,
        fanIn: fanIn.get(node.program_id) ?? 0,
        fanOut: fanOut.get(node.program_id) ?? 0,
      });
    });
  });

  return { all, placed, columns, isolated, H, lastCol: columns.length - 1, fanIn, fanOut };
}

function edgePath(a: Placed, b: Placed) {
  const x1 = a.x + 7;
  const x2 = b.x - 7;
  const c = (x2 - x1) * 0.5;
  return `M${x1},${a.y} C${x1 + c},${a.y} ${x2 - c},${b.y} ${x2},${b.y}`;
}

export function GraphView({ selected }: { selected?: string }) {
  const mode = useLayout();
  const { data, error } = usePolling(() => api.graph(), 5000);
  const top = usePolling(() => api.topProtocols(), 10000);
  const manifests = usePolling(() => api.manifests(), 30000);

  const g = useMemo(() => (data ? layout(data.nodes, data.edges) : null), [data]);

  if (error) return <Fault error={error} />;
  const loading = !data || !g;

  const edges = data?.edges ?? [];
  const node = selected && g ? (g.all.find((n) => n.program_id === selected) ?? null) : null;
  const undeclared = g ? g.all.length - (data?.nodes.length ?? 0) : 0;
  const withTraffic = g ? g.all.filter((n) => n.battle_tested_tx_count > 0).length : 0;
  const maxFan = g && g.columns.length ? Math.max(1, ...[...g.placed.values()].map((p) => p.fanIn)) : 1;
  const nameOf = new Map((g?.all ?? []).map((n) => [n.program_id, n.name]));
  const observedBy = new Map((top.data?.top ?? []).map((t) => [t.program_id, t.observed_verifications]));

  const toggle = (id: string) => navigate("graph", selected === id ? undefined : id);

  return (
    <>
      <PageHead title="Call graph" desc="Which programs declare cross-program invocation into which. Left calls right." />

      <div className="figures">
        <Figure label="Programs" value={loading ? "—" : fmt.int(g.all.length)} />
        <Figure label="CPI edges" value={loading ? "—" : fmt.int(edges.length)} />
        <Figure label="Undeclared callees" value={loading ? "—" : fmt.int(undeclared)} tone={undeclared > 0 ? "warn" : "idle"} sub="reached by CPI, no manifest" />
        <Figure label="With traffic" value={loading ? "—" : fmt.int(withTraffic)} tone={withTraffic === 0 ? "idle" : undefined} />
      </div>

      <Section title="Topology" meta={node ? node.name : loading ? undefined : "Select a program"}>
        {loading ? (
          <Skeleton rows={6} cols={3} />
        ) : g.all.length === 0 ? (
          <Empty title="The graph is empty" hint="No manifests are registered." />
        ) : mode === "phone" ? (
          <div className="graph-lists">
            {g.columns.map((col) => (
              <div key={col.role} className="graph-list">
                <h3>
                  {COLUMN_TITLES[col.role]} <span className="muted">{col.members.length}</span>
                </h3>
                <ul className="rows">
                  {col.members.map((n) => {
                    const p = g.placed.get(n.program_id)!;
                    return (
                      <li key={n.program_id} className="row">
                        <a className="row-main" href={hrefFor("graph", n.program_id)} aria-current={selected === n.program_id || undefined}>
                          <span className="row-title">
                            <i className={`mark ${markClass(n)}`} aria-hidden="true" />
                            {n.name}
                          </span>
                          <span className="row-meta">
                            <span translate="no">
                              {p.fanIn} in, {p.fanOut} out
                            </span>
                          </span>
                        </a>
                        <div className="row-side">
                          {n.manifest_version === null ? <State kind="warn">undeclared</State> : <TierBadge tier={n.trust_tier} compact />}
                        </div>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ))}
            {g.isolated.length > 0 && (
              <div className="graph-list">
                <h3>
                  No declared CPI <span className="muted">{g.isolated.length}</span>
                </h3>
                <ul className="chips">
                  {g.isolated.map((n) => (
                    <li key={n.program_id}>
                      <a className="chip" href={hrefFor("graph", n.program_id)}>
                        {n.name}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        ) : (
          <div className="graph-main">
            <svg className="graph-canvas" viewBox={`0 0 ${W} ${g.H}`} role="img" aria-label="Program CPI graph, laid out in call order">
              {g.columns.map((col, ci) => {
                const x = g.columns.length === 1 ? (X_FIRST + X_LAST) / 2 : X_FIRST + (ci / (g.columns.length - 1)) * (X_LAST - X_FIRST);
                return (
                  <text key={col.role} className="col-head" x={x} y={20} textAnchor="middle">
                    {COLUMN_TITLES[col.role]} ({col.members.length})
                  </text>
                );
              })}
              {edges.map((e, i) => {
                const a = g.placed.get(e.from);
                const b = g.placed.get(e.to);
                if (!a || !b) return null;
                const active = selected === e.from || selected === e.to;
                return <path key={`${e.from}->${e.to}-${i}`} d={edgePath(a, b)} className={active ? "edge active" : "edge"} opacity={selected && !active ? 0.12 : 1} />;
              })}
              {[...g.placed.values()].map((p) => {
                const n = p.node;
                const dim = selected !== null && selected !== undefined && selected !== n.program_id;
                const last = p.col === g.lastCol;
                const cap = last ? 24 : 32;
                const label = n.name.length > cap ? `${n.name.slice(0, cap - 1)}…` : n.name;
                return (
                  <g
                    key={n.program_id}
                    transform={`translate(${p.x}, ${p.y})`}
                    className={`node-g ${selected === n.program_id ? "active" : ""}`}
                    onClick={() => toggle(n.program_id)}
                    role="button"
                    tabIndex={0}
                    aria-label={`${n.name}, ${p.fanIn} inbound, ${p.fanOut} outbound`}
                    onKeyDown={(ev) => {
                      if (ev.key === "Enter" || ev.key === " ") {
                        ev.preventDefault();
                        toggle(n.program_id);
                      }
                    }}
                    opacity={dim ? 0.34 : 1}
                  >
                    <rect className="node-hit" x={last ? -9 : -LABEL_W} y={-ROW / 2 + 2} width={LABEL_W + 9} height={ROW - 4} />
                    {p.fanIn > 0 && <rect className="fan-bar" x={-6} y={-6 - (10 * p.fanIn) / maxFan} width={12} height={12 + (20 * p.fanIn) / maxFan} />}
                    <rect x={-5} y={-5} width={10} height={10} className={`node-mark ${markClass(n)}`} />
                    <title>{`${n.name}\n${n.program_id}\nin ${p.fanIn}, out ${p.fanOut}`}</title>
                    <text className="node-label" x={last ? 13 : -13} y={3.5} textAnchor={last ? "start" : "end"}>
                      {label}
                      {last && p.fanIn > 0 && <tspan className="node-deg"> ×{p.fanIn}</tspan>}
                    </text>
                  </g>
                );
              })}
            </svg>

            <div className="graph-legend">
              <span>
                <i className="mark" aria-hidden="true" /> registered
              </span>
              <span>
                <i className="mark hot" aria-hidden="true" /> has traffic
              </span>
              <span>
                <i className="mark undeclared" aria-hidden="true" /> undeclared callee
              </span>
              <span>
                <i className="mark quarantined" aria-hidden="true" /> quarantined
              </span>
            </div>

            {g.isolated.length > 0 && (
              <div className="graph-tray">
                <span className="graph-tray-label">No declared CPI ({g.isolated.length})</span>
                <ul className="chips">
                  {g.isolated.map((n) => (
                    <li key={n.program_id}>
                      <button type="button" className={`chip ${selected === n.program_id ? "on" : ""}`} onClick={() => toggle(n.program_id)}>
                        {n.name}
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </Section>

      <Detail open={!!selected} onClose={() => navigate("graph")} title={node ? node.name : "Unknown program"}>
        {node ? (
          node.manifest_version === null ? (
            <div className="program">
              <div className="program-id">
                <CopyId value={node.program_id} short={false} />
              </div>
              <State kind="warn">undeclared</State>
              <p className="prose">
                Reached only as a CPI target. Nothing in the registry describes it, so the gate cannot resolve its instructions: any call into it is
                unobserved code.
              </p>
              {g && (
                <dl className="kv">
                  <dt>Called by</dt>
                  <dd>{fmt.int(g.fanIn.get(node.program_id) ?? 0)} programs</dd>
                </dl>
              )}
            </div>
          ) : (
            <ProgramDetail
              node={node}
              observed={observedBy.get(node.program_id) ?? 0}
              manifest={manifests.data?.find((m) => m.protocol.program_id === node.program_id) ?? null}
              manifestsLoading={!manifests.data && !manifests.error}
              nameOf={nameOf}
            />
          )
        ) : (
          <Empty title="Not in the graph" />
        )}
      </Detail>
    </>
  );
}

function markClass(n: GraphNode): string {
  return n.quarantined ? "quarantined" : n.manifest_version === null ? "undeclared" : n.battle_tested_tx_count > 0 ? "hot" : "";
}

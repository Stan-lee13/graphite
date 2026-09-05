import { useMemo, useState } from "react";
import { usePolling } from "../usePolling";
import { api, type GraphEdge, type GraphNode } from "../api";
import {
  CopyId,
  Empty,
  ErrorState,
  Metric,
  Panel,
  State,
  TableSkeleton,
  TierBadge,
  ViewHead,
  shortId,
} from "../ui";

const W = 1000;
const PAD_T = 34;
const PAD_B = 20;
const X_FIRST = 208;
const X_LAST = 782;
const ROW = 30;
/** Widest a truncated label can draw, and so how far the row hit area reaches. */
const LABEL_W = 205;

/** Where a program sits in the invocation chain, derived purely from edges. */
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
  caller: "Invokers",
  both: "Invokes and is invoked",
  target: "Invoked",
};

/**
 * A CPI graph is not a social network — it is a call relation, and on Solana
 * that relation is overwhelmingly one-directional: many protocol programs fan
 * into a handful of system-level programs. Drawing it as a ring forces the eye
 * to trace a chord across the middle to answer "who calls the Token Program",
 * and packs thirty labels into a band where they collide.
 *
 * So this lays it out as columns by role, left to right in call order, with
 * every node label horizontal and on its own row. Reading left to right is
 * reading the direction of the invocation.
 *
 * Layout is a pure function of the node list (already sorted by the Core) and
 * the edge set, so the same graph always draws the same picture — P2 applies to
 * the view as much as to the verdict.
 */
function layout(nodes: GraphNode[], edges: GraphEdge[]) {
  const known = new Set(nodes.map((n) => n.program_id));

  // A CPI target with no manifest of its own still belongs on the picture — an
  // edge pointing into nothing would silently vanish, and an undeclared callee
  // is exactly the thing an operator needs to see.
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

  const isolated = all.filter((n) => roleOf(n.program_id) === "isolated");
  const columns: { role: Exclude<Role, "isolated">; members: GraphNode[] }[] = (
    ["caller", "both", "target"] as const
  )
    .map((role) => ({
      role,
      // Busiest first inside a column: the programs carrying the most edges sit
      // at the top where the eye lands, and the ordering is stable because the
      // tie-break falls through to the Core's own sort order.
      members: all
        .filter((n) => roleOf(n.program_id) === role)
        .sort(
          (a, b) =>
            (fanIn.get(b.program_id) ?? 0) +
            (fanOut.get(b.program_id) ?? 0) -
            ((fanIn.get(a.program_id) ?? 0) + (fanOut.get(a.program_id) ?? 0)),
        ),
    }))
    .filter((c) => c.members.length > 0);

  const tallest = columns.reduce((m, c) => Math.max(m, c.members.length), 1);
  const H = Math.max(PAD_T + PAD_B + (tallest - 1) * ROW + 20, 320);
  const top = PAD_T + 10;
  const bottom = H - PAD_B;

  const placed = new Map<string, Placed>();
  columns.forEach((col, ci) => {
    const x =
      columns.length === 1
        ? (X_FIRST + X_LAST) / 2
        : X_FIRST + (ci / (columns.length - 1)) * (X_LAST - X_FIRST);
    const span = (col.members.length - 1) * ROW;
    // Short columns are centred against the tallest one so the fan reads as a
    // funnel rather than as two lists that happen to start at the same line.
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

  return { all, placed, columns, isolated, H, lastCol: columns.length - 1 };
}

/** Cubic bezier between two placed nodes, flattened near the endpoints so the
 *  line leaves and enters horizontally and the fan stays readable. */
function edgePath(a: Placed, b: Placed) {
  const x1 = a.x + 7;
  const x2 = b.x - 7;
  const c = (x2 - x1) * 0.5;
  return `M${x1},${a.y} C${x1 + c},${a.y} ${x2 - c},${b.y} ${x2},${b.y}`;
}

export function GraphView() {
  const { data, error } = usePolling(() => api.graph(), 5000);
  const [selected, setSelected] = useState<string | null>(null);

  const g = useMemo(
    () =>
      data
        ? layout(data.nodes, data.edges)
        : {
            all: [] as GraphNode[],
            placed: new Map<string, Placed>(),
            columns: [] as { role: Exclude<Role, "isolated">; members: GraphNode[] }[],
            isolated: [] as GraphNode[],
            H: 320,
            lastCol: 0,
          },
    [data],
  );

  if (error) return <ErrorState message={error} />;
  const loading = !data;

  const node = g.all.find((n) => n.program_id === selected) ?? null;
  const edges = data?.edges ?? [];
  const observed = g.all.filter((n) => n.battle_tested_tx_count > 0).length;
  const maxFan = g.columns.length
    ? Math.max(1, ...[...g.placed.values()].map((p) => p.fanIn))
    : 1;

  const toggle = (id: string) => setSelected(selected === id ? null : id);

  return (
    <>
      <ViewHead title="Semantic graph" note="declared CPI edges, drawn in call order">
        <Metric label="Nodes" value={loading ? "—" : g.all.length} />
        <Metric label="CPI edges" value={loading ? "—" : edges.length} />
        <Metric
          label="Undeclared callees"
          value={loading ? "—" : g.all.length - (data?.nodes.length ?? 0)}
          tone={g.all.length - (data?.nodes.length ?? 0) > 0 ? "warn" : "idle"}
          sub="no manifest of their own"
        />
        <Metric
          label="With traffic"
          value={loading ? "—" : observed}
          tone={observed === 0 ? "idle" : undefined}
        />
      </ViewHead>

      <div className="body">
        <Panel title="CPI topology" meta={node ? node.name : "select a node"}>
          {loading ? (
            <TableSkeleton rows={6} cols={3} />
          ) : g.all.length === 0 ? (
            <Empty title="Graph is empty" hint="No manifests are registered." />
          ) : (
            <div className="graph-split">
              <div className="graph-main">
                <svg
                  className="graph-canvas"
                  viewBox={`0 0 ${W} ${g.H}`}
                  role="img"
                  aria-label="Program CPI graph, laid out in call order"
                >
                  {g.columns.map((col, ci) => {
                    const x =
                      g.columns.length === 1
                        ? (X_FIRST + X_LAST) / 2
                        : X_FIRST + (ci / (g.columns.length - 1)) * (X_LAST - X_FIRST);
                    return (
                      <text
                        key={col.role}
                        className="col-head"
                        x={x}
                        y={20}
                        textAnchor="middle"
                      >
                        {COLUMN_TITLES[col.role]} · {col.members.length}
                      </text>
                    );
                  })}

                  {edges.map((e, i) => {
                    const a = g.placed.get(e.from);
                    const b = g.placed.get(e.to);
                    if (!a || !b) return null;
                    const active = selected === e.from || selected === e.to;
                    return (
                      <path
                        key={`${e.from}->${e.to}-${i}`}
                        d={edgePath(a, b)}
                        className={active ? "edge active" : "edge"}
                        opacity={selected && !active ? 0.12 : 1}
                      />
                    );
                  })}

                  {[...g.placed.values()].map((p) => {
                    const n = p.node;
                    const dim = selected !== null && selected !== n.program_id;
                    const last = p.col === g.lastCol;
                    // The right column also carries a fan-in count, so it gets
                    // less room for the name than the columns that do not.
                    const cap = last ? 24 : 32;
                    const label =
                      n.name.length > cap ? `${n.name.slice(0, cap - 1)}…` : n.name;
                    return (
                      <g
                        key={n.program_id}
                        transform={`translate(${p.x}, ${p.y})`}
                        className={`node-g ${selected === n.program_id ? "active" : ""}`}
                        onClick={() => toggle(n.program_id)}
                        role="button"
                        tabIndex={0}
                        aria-label={`${n.name}, ${p.fanIn} inbound, ${p.fanOut} outbound CPI edges`}
                        onKeyDown={(ev) => {
                          if (ev.key === "Enter" || ev.key === " ") {
                            ev.preventDefault();
                            toggle(n.program_id);
                          }
                        }}
                        opacity={dim ? 0.34 : 1}
                      >
                        {/* A 10px marker is not a target anyone can hit. The
                            whole row — marker and label — is the hit area. */}
                        <rect
                          className="node-hit"
                          x={last ? -9 : -LABEL_W}
                          y={-ROW / 2 + 2}
                          width={LABEL_W + 9}
                          height={ROW - 4}
                        />
                        {/* Fan-in weight, drawn behind the marker. The Token
                            Program pulling 22 edges should look different from
                            one pulling 1 without the reader counting lines. */}
                        {p.fanIn > 0 && (
                          <rect
                            className="fan-bar"
                            x={-6}
                            y={-6 - (10 * p.fanIn) / maxFan}
                            width={12}
                            height={12 + (20 * p.fanIn) / maxFan}
                          />
                        )}
                        <rect
                          x={-5}
                          y={-5}
                          width={10}
                          height={10}
                          className={
                            n.quarantined
                              ? "node-mark quarantined"
                              : n.manifest_version === null
                                ? "node-mark undeclared"
                                : n.battle_tested_tx_count > 0
                                  ? "node-mark hot"
                                  : "node-mark"
                          }
                        />
                        <title>{`${n.name}\n${n.program_id}\n${n.trust_tier}\nin ${p.fanIn} · out ${p.fanOut}`}</title>
                        <text
                          className="node-label"
                          x={last ? 13 : -13}
                          y={3.5}
                          textAnchor={last ? "start" : "end"}
                        >
                          {label}
                          {last && p.fanIn > 0 && (
                            <tspan className="node-deg"> ×{p.fanIn}</tspan>
                          )}
                        </text>
                      </g>
                    );
                  })}
                </svg>

                {g.isolated.length > 0 && (
                  <div className="graph-tray">
                    <span className="graph-tray-label">
                      No declared CPI edges · {g.isolated.length}
                    </span>
                    {g.isolated.map((n) => (
                      <button
                        key={n.program_id}
                        type="button"
                        className={`chip ${selected === n.program_id ? "on" : ""}`}
                        onClick={() => toggle(n.program_id)}
                      >
                        {n.name}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              <aside className="graph-side">
                {node ? (
                  <>
                    <div style={{ fontWeight: 600, fontSize: 14 }}>{node.name}</div>
                    <div style={{ margin: "6px 0 12px" }}>
                      <CopyId value={node.program_id} short={false} />
                    </div>
                    <TierBadge tier={node.trust_tier} />
                    {node.manifest_version === null && (
                      <div style={{ marginTop: 10 }}>
                        <State kind="warn">no manifest</State>
                        <div className="graph-note">
                          Reached only as a CPI target. Nothing in the registry
                          describes it, so L6 cannot resolve its instructions.
                        </div>
                      </div>
                    )}
                    {node.quarantined && (
                      <div style={{ marginTop: 10 }}>
                        <State kind="block">quarantined</State>
                        {node.quarantine_reason && (
                          <div className="graph-note">{node.quarantine_reason}</div>
                        )}
                      </div>
                    )}
                    <dl className="kv">
                      <dt>Manifest version</dt>
                      <dd>{node.manifest_version ?? "—"}</dd>
                      <dt>Instructions</dt>
                      <dd>{node.instruction_count}</dd>
                      <dt>Baseline samples</dt>
                      <dd>{node.baseline_samples ?? "—"}</dd>
                      <dt>Battle-tested tx</dt>
                      <dd>{node.battle_tested_tx_count.toLocaleString()}</dd>
                      <dt>Community verified</dt>
                      <dd>{node.community_verified_count}</dd>
                      <dt>CPI edges</dt>
                      <dd>
                        {g.placed.get(node.program_id)
                          ? `in ${g.placed.get(node.program_id)!.fanIn} · out ${
                              g.placed.get(node.program_id)!.fanOut
                            }`
                          : "none"}
                      </dd>
                      {node.cpi_targets.length > 0 && (
                        <>
                          <dt>Declared CPI targets</dt>
                          <dd>
                            <ul>
                              {node.cpi_targets.map((t) => (
                                <li key={t}>
                                  {g.placed.get(t)?.node.name ?? shortId(t, 8, 5)}
                                </li>
                              ))}
                            </ul>
                          </dd>
                        </>
                      )}
                    </dl>
                  </>
                ) : (
                  <div className="graph-legend">
                    <p style={{ marginTop: 0 }}>
                      Columns follow the direction of invocation: programs on the
                      left declare CPI into programs on their right. Select a node
                      to isolate its edges.
                    </p>
                    <dl>
                      <dt>
                        <i className="key-mark" /> registered
                      </dt>
                      <dd>a manifest describes every instruction</dd>
                      <dt>
                        <i className="key-mark hot" /> observed
                      </dt>
                      <dd>the gate has seen mainnet traffic on it</dd>
                      <dt>
                        <i className="key-mark undeclared" /> undeclared
                      </dt>
                      <dd>a CPI target with no manifest of its own</dd>
                      <dt>
                        <i className="key-mark quarantined" /> quarantined
                      </dt>
                      <dd>withdrawn from trust pending review</dd>
                    </dl>
                  </div>
                )}
              </aside>
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}

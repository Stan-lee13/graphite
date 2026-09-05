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
  TierBadge,
  ViewHead,
  tierRank,
} from "../ui";

export function ProtocolsView() {
  const top = usePolling(() => api.topProtocols(), 5000);
  const graph = usePolling(() => api.graph(), 5000);

  const error = top.error ?? graph.error;
  if (error) return <ErrorState message={error} />;

  const loading = !top.data || !graph.data;

  const observedBy = new Map(
    (top.data?.top ?? []).map((t) => [t.program_id, t.observed_verifications]),
  );
  const rows = [...(graph.data?.nodes ?? [])]
    .map((node) => ({ node, observed: observedBy.get(node.program_id) ?? 0 }))
    // Most-exercised first: what the gate actually sees traffic on is more
    // useful at the top than alphabetical order.
    .sort(
      (a, b) =>
        b.observed - a.observed ||
        b.node.battle_tested_tx_count - a.node.battle_tested_tx_count,
    );

  const quarantined = rows.filter((r) => r.node.quarantined).length;
  const withBaseline = rows.filter((r) => (r.node.baseline_samples ?? 0) > 0).length;
  const trusted = rows.filter((r) => tierRank(r.node.trust_tier) >= 3).length;

  return (
    <>
      <ViewHead
        title="Protocols"
        note={loading ? "loading" : `${rows.length} in the semantic graph`}
      >
        <Metric label="Programs" value={loading ? "—" : rows.length} />
        <Metric
          label="Trusted tier 3+"
          value={loading ? "—" : trusted}
          sub={loading ? undefined : `of ${rows.length}`}
        />
        <Metric
          label="Simulation baseline"
          value={loading ? "—" : withBaseline}
          sub="programs with earned samples"
          tone={!loading && withBaseline === 0 ? "idle" : undefined}
        />
        <Metric
          label="Quarantined"
          value={loading ? "—" : quarantined}
          tone={quarantined > 0 ? "block" : "idle"}
        />
      </ViewHead>

      <div className="body">
        <Panel
          title="Registered programs"
          meta={loading ? "" : "ranked by observed verifications"}
          flush
        >
          {loading ? (
            <TableSkeleton rows={8} cols={6} />
          ) : rows.length === 0 ? (
            <Empty
              title="No programs in the graph"
              hint="Seed manifests load at startup — if this is empty the Core may have failed to boot its registry."
            />
          ) : (
            <table className="data">
              <thead>
                <tr>
                  <th>Protocol</th>
                  <th>Program</th>
                  <th>Trust</th>
                  <th className="n">Instr</th>
                  <th className="n">Baseline</th>
                  <th className="n">Battle-tested</th>
                  <th className="n">Observed</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                {rows.map(({ node, observed }) => (
                  <tr
                    key={node.program_id}
                    className={node.quarantined ? "row-flag" : undefined}
                  >
                    <td>
                      <span className="primary">{node.name}</span>
                      {node.manifest_version && (
                        <span className="secondary">v{node.manifest_version}</span>
                      )}
                    </td>
                    <td className="id">
                      <CopyId value={node.program_id} />
                    </td>
                    <td>
                      <TierBadge tier={node.trust_tier} />
                    </td>
                    <td className="n">{node.instruction_count}</td>
                    <td className="n">
                      {node.baseline_samples === null || node.baseline_samples === 0 ? (
                        <span style={{ color: "var(--ink-3)" }}>—</span>
                      ) : (
                        node.baseline_samples
                      )}
                    </td>
                    <td className="n">{node.battle_tested_tx_count.toLocaleString()}</td>
                    <td className="n">
                      {observed === 0 ? (
                        <span style={{ color: "var(--ink-3)" }}>0</span>
                      ) : (
                        observed.toLocaleString()
                      )}
                    </td>
                    <td>
                      {node.quarantined ? (
                        <State kind="block">
                          <span title={node.quarantine_reason ?? undefined}>
                            quarantined
                          </span>
                        </State>
                      ) : (
                        <State kind="pass">active</State>
                      )}
                    </td>
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

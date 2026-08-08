import { usePolling, formatTime } from "../usePolling";
import { api } from "../api";
import { ErrorState, Loading, TierBadge, shortId } from "../ui";

export function ProtocolsView() {
  const { data, error, loading } = usePolling(() => api.topProtocols(), 5000);
  const graph = usePolling(() => api.graph(), 5000);

  if (error) return <ErrorState message={error} />;
  if (loading || !data || !graph.data) return <Loading what="protocols" />;

  // Merge top-5 volume ranking with the full node list (tiers, evidence).
  const topIds = new Map(data.top.map((t) => [t.program_id, t]));
  const rows = [...graph.data.nodes]
    .map((n) => ({
      node: n,
      observed: topIds.get(n.program_id)?.observed_verifications ?? 0,
    }))
    .sort((a, b) => b.node.battle_tested_tx_count - a.node.battle_tested_tx_count);

  const totalBt = rows.reduce((s, r) => s + r.node.battle_tested_tx_count, 0);

  return (
    <section>
      <div className="view-head">
        <h2>Protocol Overview</h2>
        <span className="muted">
          {rows.length} programs · {totalBt.toLocaleString()} battle-tested tx earned
        </span>
      </div>
      <div className="card">
        <table className="table">
          <thead>
            <tr>
              <th>Protocol</th>
              <th>Program ID</th>
              <th>Trust Tier</th>
              <th>Instrs</th>
              <th>Baseline samples</th>
              <th>Battle-tested tx</th>
              <th>Observed verifications</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(({ node, observed }) => (
              <tr key={node.program_id} className={node.quarantined ? "row-quarantined" : ""}>
                <td className="cell-name">
                  <span className="name">{node.name}</span>
                  {node.manifest_version && (
                    <span className="ver">v{node.manifest_version}</span>
                  )}
                </td>
                <td className="mono" title={node.program_id}>{shortId(node.program_id)}</td>
                <td><TierBadge tier={node.trust_tier} /></td>
                <td>{node.instruction_count}</td>
                <td>{node.baseline_samples ?? "—"}</td>
                <td>{node.battle_tested_tx_count.toLocaleString()}</td>
                <td>{observed.toLocaleString()}</td>
                <td>
                  {node.quarantined ? (
                    <span className="pill quarantined" title={node.quarantine_reason ?? ""}>
                      quarantined
                    </span>
                  ) : (
                    <span className="pill ok">active</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="muted small">
          Updated {formatTime(new Date().toISOString())} · data is read-only (P4)
        </p>
      </div>
    </section>
  );
}

import { usePolling } from "../usePolling";
import { api } from "../api";
import { ErrorState, Loading, TierBadge, shortId } from "../ui";

export function RegistryView() {
  const { data, error, loading } = usePolling(() => api.registry(), 5000);

  if (error) return <ErrorState message={error} />;
  if (loading || !data) return <Loading what="manifest registry" />;

  return (
    <section>
      <div className="view-head">
        <h2>Manifest Registry</h2>
        <span className="muted">
          {data.record_count} accepted submissions · {data.reviewers.length} reviewers
        </span>
      </div>

      <div className="card">
        <h3>Accepted submissions (append-only, P4)</h3>
        {data.records.length === 0 ? (
          <p className="muted">
            No submissions yet — the community registry workflow (Phase 2/3)
            populates this read-only view. Version lineage and content hashes
            are pinned per Constitution P4/G7.
          </p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Program</th>
                <th>Version</th>
                <th>Previous ref</th>
                <th>Content hash</th>
                <th>Trust tier</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {data.records.map((r, i) => (
                <tr key={i}>
                  <td className="mono" title={r.program_id}>{shortId(r.program_id, 10, 6)}</td>
                  <td>v{r.version_label}</td>
                  <td className="mono small">{r.previous_version_ref ? shortId(r.previous_version_ref, 6, 4) : "—"}</td>
                  <td className="mono small">{shortId(r.content_hash, 8, 6)}</td>
                  <td><TierBadge tier={r.trust_tier} /></td>
                  <td>{r.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card">
        <h3>Registered reviewers</h3>
        {data.reviewers.length === 0 ? (
          <p className="muted">No reviewers registered yet.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Reviewer</th>
                <th>Reputation score</th>
              </tr>
            </thead>
            <tbody>
              {data.reviewers.map((r) => (
                <tr key={r.pubkey}>
                  <td className="mono">{shortId(r.pubkey, 12, 8)}</td>
                  <td>{r.reputation_score.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}

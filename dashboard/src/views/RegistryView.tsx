import { usePolling } from "../usePolling";
import { api } from "../api";
import {
  CopyId,
  Empty,
  ErrorState,
  Metric,
  Panel,
  TableSkeleton,
  TierBadge,
  ViewHead,
} from "../ui";

export function RegistryView() {
  const { data, error } = usePolling(() => api.registry(), 5000);

  if (error) return <ErrorState message={error} />;
  const loading = !data;

  const records = data?.records ?? [];
  const reviewers = data?.reviewers ?? [];
  const community = records.filter((r) => r.source !== "seed").length;

  return (
    <>
      <ViewHead
        title="Registry"
        note="append-only submission history and the reviewers who attested to it"
      >
        <Metric label="Submissions" value={loading ? "—" : data.record_count} />
        <Metric
          label="Community"
          value={loading ? "—" : community}
          tone={community === 0 ? "idle" : undefined}
          sub="non-seed manifests"
        />
        <Metric
          label="Reviewers"
          value={loading ? "—" : reviewers.length}
          tone={reviewers.length === 0 ? "idle" : undefined}
        />
      </ViewHead>

      <div className="body">
        <Panel
          title="Accepted submissions"
          meta="append-only — records are never rewritten"
          flush
        >
          {loading ? (
            <TableSkeleton rows={4} cols={5} />
          ) : records.length === 0 ? (
            <Empty
              title="No submissions recorded"
              hint="Shipped seed manifests load directly at startup and are immutable at runtime; this table records manifests accepted through the reviewed submission path."
            />
          ) : (
            <table className="data">
              <thead>
                <tr>
                  <th>Program</th>
                  <th>Version</th>
                  <th>Supersedes</th>
                  <th>Content hash</th>
                  <th>Trust</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                {records.map((r, i) => (
                  <tr key={`${r.program_id}-${r.version_label}-${i}`}>
                    <td className="id">
                      <CopyId value={r.program_id} />
                    </td>
                    <td className="primary">v{r.version_label}</td>
                    <td className="id">
                      {r.previous_version_ref ? (
                        <CopyId value={r.previous_version_ref} />
                      ) : (
                        <span style={{ color: "var(--ink-3)" }}>first</span>
                      )}
                    </td>
                    <td className="id">
                      <CopyId value={r.content_hash} />
                    </td>
                    <td>
                      <TierBadge tier={r.trust_tier} />
                    </td>
                    <td>{r.source}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>

        <Panel title="Registered reviewers" meta={loading ? "" : `${reviewers.length}`} flush>
          {loading ? (
            <TableSkeleton rows={3} cols={2} />
          ) : reviewers.length === 0 ? (
            <Empty
              title="No reviewers registered"
              hint="Reviewers are registered by the operator and their attestations gate community submissions. Reputation is evidence, not authority — it never sets a trust tier directly."
            />
          ) : (
            <table className="data">
              <thead>
                <tr>
                  <th>Reviewer</th>
                  <th className="n">Reputation</th>
                </tr>
              </thead>
              <tbody>
                {[...reviewers]
                  .sort((a, b) => b.reputation_score - a.reputation_score)
                  .map((r) => (
                    <tr key={r.pubkey}>
                      <td className="id">
                        <CopyId value={r.pubkey} />
                      </td>
                      <td className="n">{r.reputation_score.toLocaleString()}</td>
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

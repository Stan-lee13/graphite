// The append-only submission history and the reviewers who attested to it.

import { api } from "../api";
import { hrefFor } from "../router";
import { useLayout, usePolling } from "../usePolling";
import { CopyId, Empty, Fault, Figure, PageHead, Section, Skeleton, TierBadge, fmt } from "../ui";

export function RegistryView() {
  const layout = useLayout();
  const { data, error } = usePolling(() => api.registry(), 5000);
  const graph = usePolling(() => api.graph(), 30000);
  if (error) return <Fault error={error} />;
  const loading = !data;

  const records = data?.records ?? [];
  const reviewers = [...(data?.reviewers ?? [])].sort((a, b) => b.reputation_score - a.reputation_score);
  const community = records.filter((r) => r.source !== "seed").length;
  const nameOf = new Map((graph.data?.nodes ?? []).map((n) => [n.program_id, n.name]));

  return (
    <>
      <PageHead title="Registry" desc="Manifests accepted through the reviewed submission path. Records are appended, never rewritten." />

      <div className="figures">
        <Figure label="Submissions" value={loading ? "—" : fmt.int(data.record_count)} />
        <Figure label="From the community" value={loading ? "—" : fmt.int(community)} tone={community === 0 ? "idle" : undefined} sub="not shipped as seed" />
        <Figure label="Reviewers" value={loading ? "—" : fmt.int(reviewers.length)} tone={reviewers.length === 0 ? "idle" : undefined} />
      </div>

      <Section title="Accepted submissions" flush>
        {loading ? (
          <Skeleton rows={4} cols={5} />
        ) : records.length === 0 ? (
          <Empty
            title="No submissions recorded"
            hint="Shipped seed manifests load directly at startup and are immutable at runtime. This table records manifests accepted through review."
          />
        ) : layout === "phone" ? (
          <ul className="rows">
            {records.map((r, i) => (
              <li key={`${r.program_id}-${r.version_label}-${i}`} className="row">
                <a className="row-main" href={hrefFor("programs", r.program_id)}>
                  <span className="row-title">
                    {nameOf.get(r.program_id) ?? r.program_id.slice(0, 10) + "…"} <span className="row-sub">v{r.version_label}</span>
                  </span>
                  <span className="row-meta">
                    <span>{r.source}</span>
                    <CopyId value={r.content_hash} />
                  </span>
                </a>
                <div className="row-side">
                  <TierBadge tier={r.trust_tier} compact />
                </div>
              </li>
            ))}
          </ul>
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
                  <td>
                    <a className="cell-link" href={hrefFor("programs", r.program_id)}>
                      {nameOf.get(r.program_id) ?? <CopyId value={r.program_id} />}
                    </a>
                  </td>
                  <td translate="no">v{r.version_label}</td>
                  <td className="id">{r.previous_version_ref ? <CopyId value={r.previous_version_ref} /> : <span className="muted">first</span>}</td>
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
      </Section>

      <Section title="Reviewers" meta={loading ? undefined : fmt.int(reviewers.length)} flush>
        {loading ? (
          <Skeleton rows={3} cols={2} />
        ) : reviewers.length === 0 ? (
          <Empty
            title="No reviewers registered"
            hint="The operator registers reviewers; their attestations gate community submissions. Reputation is evidence, not authority: it never sets a trust tier by itself."
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
              {reviewers.map((r) => (
                <tr key={r.pubkey}>
                  <td className="id">
                    <CopyId value={r.pubkey} />
                  </td>
                  <td className="n">{fmt.int(r.reputation_score)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>
    </>
  );
}

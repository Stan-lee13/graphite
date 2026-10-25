// Every program the gate knows, and — one click deeper — the manifest that
// tells the gate what each of its instructions is allowed to do. The manifest
// is the whole basis of a verdict, so an operator reading a refusal needs to
// be able to open it without leaving the console.

import { useMemo, useState } from "react";
import { ChevronDown, ExternalLink, Search } from "lucide-react";
import { api, type GraphNode, type Manifest, type ManifestInstruction } from "../api";
import { hrefFor, navigate } from "../router";
import { MANIFESTS_POLL_MS } from "../poll-state";
import { useLayout, usePolling } from "../usePolling";
import { CopyId, Detail, Empty, Fault, Figure, Freshness, PageHead, Section, Skeleton, State, TierBadge, fmt, pollFault, tierRank } from "../ui";

export function ProgramsView({ selected }: { selected?: string }) {
  const layout = useLayout();
  const top = usePolling(() => api.topProtocols(), 5000);
  const graph = usePolling(() => api.graph(), 5000);
  // Round 30: `/manifests` is every manifest in full (about 4.6 MB for the
  // shipped set) and changes only on a registry update or restart; it was
  // refetched every 30 s for as long as this view was open.
  const manifests = usePolling(() => api.manifests(), MANIFESTS_POLL_MS);
  const [q, setQ] = useState("");

  const fault = pollFault(top, graph);
  if (fault) return <Fault error={fault} title="Programs" />;
  const loading = !top.data || !graph.data;

  // Round 29 (audit 2026-10-20, D10): a program `/api/protocols/top` did not
  // return has an unknown count — not zero, and not "no traffic". Round 30:
  // the console asks for every row (`?limit=500`), so on a current Core
  // every program has its count; the unknown case remains for older Cores
  // that ignore the limit and send five.
  const observedBy = new Map((top.data?.top ?? []).map((t) => [t.program_id, t.observed_verifications]));
  const all = [...(graph.data?.nodes ?? [])]
    .map((node) => ({ node, observed: observedBy.get(node.program_id) }))
    // Most-exercised first: what the gate actually sees traffic on matters
    // more at the top than alphabetical order.
    .sort((a, b) => (b.observed ?? -1) - (a.observed ?? -1) || b.node.battle_tested_tx_count - a.node.battle_tested_tx_count);

  const needle = q.trim().toLowerCase();
  const rows = needle
    ? all.filter((r) => r.node.name.toLowerCase().includes(needle) || r.node.program_id.toLowerCase().startsWith(needle))
    : all;

  const quarantined = all.filter((r) => r.node.quarantined).length;
  const withBaseline = all.filter((r) => (r.node.baseline_samples ?? 0) > 0).length;
  const trusted = all.filter((r) => tierRank(r.node.trust_tier) >= 3).length;

  const open = selected ? all.find((r) => r.node.program_id === selected) : undefined;
  const manifest = selected ? manifests.data?.find((m) => m.protocol.program_id === selected) : undefined;
  const nameOf = new Map(all.map((r) => [r.node.program_id, r.node.name]));

  return (
    <>
      <PageHead
        title="Programs"
        desc="Every program in the semantic graph, the most verified here first, then by mainnet census."
        actions={
          <label className="search-field">
            <Search aria-hidden="true" />
            <input
              type="search"
              name="program"
              value={q}
              placeholder="Filter by name or program ID…"
              autoComplete="off"
              spellCheck={false}
              aria-label="Filter programs"
              onChange={(e) => setQ(e.target.value)}
            />
          </label>
        }
      />

      <Freshness sources={[top, graph]} />

      <div className="figures">
        <Figure label="Programs" value={loading ? "—" : fmt.int(all.length)} />
        <Figure label="Tier 3 or above" value={loading ? "—" : fmt.int(trusted)} sub={loading ? undefined : `of ${all.length}`} />
        <Figure label="With a baseline" value={loading ? "—" : fmt.int(withBaseline)} sub="earned simulation samples" tone={!loading && withBaseline === 0 ? "idle" : undefined} />
        <Figure label="Quarantined" value={loading ? "—" : fmt.int(quarantined)} tone={quarantined > 0 ? "block" : "idle"} />
      </div>

      <Section title="Registered programs" meta={loading ? undefined : needle ? `${rows.length} of ${all.length}` : `${all.length}`} flush>
        {loading ? (
          <Skeleton rows={8} cols={6} />
        ) : rows.length === 0 ? (
          needle ? (
            <Empty title={`Nothing matches “${q}”`} hint="Try the start of the program ID, or part of the protocol name." />
          ) : (
            <Empty title="No programs in the graph" hint="Seed manifests load at startup. An empty graph means the Core failed to boot its registry." />
          )
        ) : layout === "phone" ? (
          <ul className="rows">
            {rows.map(({ node, observed }) => (
              <li key={node.program_id} className="row">
                <a className="row-main" href={hrefFor("programs", node.program_id)}>
                  <span className="row-title">
                    {node.name}
                    {node.manifest_version && <span className="row-sub">{versionLabel(node.manifest_version)}</span>}
                  </span>
                  <span className="row-meta">
                    <span translate="no">{node.instruction_count} instructions</span>
                    <span>{observedText(observed)}</span>
                  </span>
                </a>
                <div className="row-side">
                  {node.quarantined ? <State kind="block">quarantined</State> : <TierBadge tier={node.trust_tier} compact />}
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <table className="data">
            <thead>
              <tr>
                <th>Program</th>
                <th>ID</th>
                <th>Trust</th>
                <th className="n">Instructions</th>
                <th className="n">Baseline</th>
                <th className="n">Mainnet census</th>
                <th className="n">Verified here</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ node, observed }) => (
                // Round 30 (axe aria-prohibited-attr): aria-selected belongs to
                // grid rows, not a table's; the open row's link says it instead.
                <tr key={node.program_id} className={node.quarantined ? "flag" : undefined}>
                  <td>
                    <a className="cell-link" href={hrefFor("programs", node.program_id)} aria-current={selected === node.program_id || undefined}>
                      {node.name}
                      {node.manifest_version && <span className="row-sub">{versionLabel(node.manifest_version)}</span>}
                    </a>
                    {node.quarantined && (
                      <State kind="block" title={node.quarantine_reason ?? undefined}>
                        quarantined
                      </State>
                    )}
                  </td>
                  <td className="id">
                    <CopyId value={node.program_id} />
                  </td>
                  <td>
                    <TierBadge tier={node.trust_tier} />
                  </td>
                  <td className="n">{node.instruction_count}</td>
                  <td className="n">{node.baseline_samples ? fmt.int(node.baseline_samples) : <span className="muted">—</span>}</td>
                  <td className="n">{node.battle_tested_tx_count ? fmt.int(node.battle_tested_tx_count) : <span className="muted">0</span>}</td>
                  <td className="n">{observed === undefined ? <span className="muted" title={NOT_REPORTED}>—</span> : observed ? fmt.int(observed) : <span className="muted">0</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      {/* Round 39 (R39-DASH-1): a deep link opened before the graph had
          answered said "Not in the graph: no manifest describes this program
          ID" about a program nobody had looked up yet. */}
      <Detail
        open={!!selected}
        onClose={() => navigate("programs")}
        title={loading ? "Loading…" : open ? open.node.name : selected ? "Unknown program" : ""}
      >
        {loading ? (
          <Skeleton rows={6} cols={2} />
        ) : open ? (
          <ProgramDetail
            node={open.node}
            observed={open.observed}
            manifest={manifest ?? null}
            manifestsLoading={!manifests.data && !manifests.error}
            nameOf={nameOf}
          />
        ) : (
          <Empty title="Not in the graph" hint="No manifest describes this program ID." />
        )}
      </Detail>
    </>
  );
}

/** "1.2.0" reads as v1.2.0; "native" is not a number and gets no prefix. */
export function versionLabel(v: string): string {
  return /^\d/.test(v) ? `v${v}` : v;
}

/**
 * A manifest URL the console will render as a link: http(s) only. The Core
 * refuses other schemes at manifest load (Round 17, F-16-10); this is the
 * same rule at the point of rendering, so a `javascript:` or `data:` value
 * from any source is text at most, never an href.
 */
function httpUrl(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  try {
    const u = new URL(raw);
    return u.protocol === "https:" || u.protocol === "http:" ? u.href : undefined;
  } catch {
    return undefined;
  }
}

const NOT_REPORTED = "This Core did not report a verification count for this program (a Core before Round 29 reports only its top five).";

function observedText(observed: number | undefined): string {
  if (observed === undefined) return "count not reported";
  return observed > 0 ? `${fmt.int(observed)} verifications` : "not verified here yet";
}

export function ProgramDetail({
  node,
  observed,
  manifest,
  manifestsLoading,
  nameOf,
}: {
  node: GraphNode;
  /** Undefined when `/api/protocols/top` did not report this program. */
  observed: number | undefined;
  manifest: Manifest | null;
  manifestsLoading: boolean;
  nameOf: Map<string, string>;
}) {
  return (
    <div className="program">
      <div className="program-id">
        <CopyId value={node.program_id} short={false} />
      </div>

      <div className="program-status">
        {node.quarantined ? <State kind="block">quarantined</State> : <State kind="pass">active</State>}
        <TierBadge tier={node.trust_tier} />
      </div>
      {node.quarantined && node.quarantine_reason && <p className="prose warn-text">{node.quarantine_reason}</p>}

      {manifest && (httpUrl(manifest.protocol.website) || httpUrl(manifest.protocol.github)) && (
        <div className="program-links">
          {httpUrl(manifest.protocol.website) && (
            <a href={httpUrl(manifest.protocol.website)} target="_blank" rel="noreferrer noopener">
              Website <ExternalLink aria-hidden="true" />
            </a>
          )}
          {httpUrl(manifest.protocol.github) && (
            <a href={httpUrl(manifest.protocol.github)} target="_blank" rel="noreferrer noopener">
              Source <ExternalLink aria-hidden="true" />
            </a>
          )}
        </div>
      )}

      <dl className="kv">
        <dt>Manifest</dt>
        <dd translate="no">{node.manifest_version ? versionLabel(node.manifest_version) : "none"}</dd>
        <dt>Verified here</dt>
        <dd title={observed === undefined ? NOT_REPORTED : undefined}>{observed === undefined ? "not reported" : fmt.int(observed)}</dd>
        <dt>Baseline samples</dt>
        <dd>{node.baseline_samples ? fmt.int(node.baseline_samples) : "none yet"}</dd>
        <dt>Mainnet census</dt>
        <dd>{fmt.int(node.battle_tested_tx_count)}</dd>
        <dt>Community verified</dt>
        {/* Round 39: a Core that does not send it drew "NaN". */}
        <dd>{node.community_verified_count == null ? "not reported" : fmt.int(node.community_verified_count)}</dd>
        {manifest && manifest.protocol.category && (
          <>
            <dt>Category</dt>
            <dd>{manifest.protocol.category}</dd>
          </>
        )}
      </dl>

      {node.cpi_targets.length > 0 && (
        <div className="program-block">
          <h3>Declares CPI into</h3>
          <ul className="chips">
            {node.cpi_targets.map((t) => (
              <li key={t}>
                <a className="chip" href={hrefFor("programs", t)}>
                  {nameOf.get(t) ?? t.slice(0, 8) + "…"}
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="program-block">
        <h3>
          Instructions{manifest ? ` (${manifest.instructions.length})` : ""}
        </h3>
        {manifestsLoading ? (
          <Skeleton rows={4} cols={2} />
        ) : !manifest ? (
          // Round 39: a program the graph knows only from observed behaviour
          // has no manifest at all; that is not the same as one this Core
          // did not send.
          <p className="prose muted">
            {node.manifest_version === null
              ? "No manifest describes this program, so the gate cannot resolve its instructions."
              : "The manifest is not readable from this Core, so the instruction list cannot be shown."}
          </p>
        ) : (
          <ul className="instructions">
            {manifest.instructions.map((ix) => (
              <Instruction key={ix.discriminator + ix.name} ix={ix} nameOf={nameOf} />
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function Instruction({ ix, nameOf }: { ix: ManifestInstruction; nameOf: Map<string, string> }) {
  const flags = useMemo(
    () => ix.accounts.filter((a) => a.is_writable).length + " writable, " + ix.accounts.filter((a) => a.is_signer).length + " signer",
    [ix.accounts],
  );
  return (
    <li>
      <details className="ix">
        <summary>
          <span className="ix-name">{ix.name}</span>
          <span className="ix-disc" translate="no">
            {ix.discriminator}
          </span>
          {ix.risk_class && <span className={`risk-class ${ix.risk_class}`}>{ix.risk_class.replace(/_/g, " ")}</span>}
          <ChevronDown className="ix-chevron" aria-hidden="true" />
        </summary>
        <div className="ix-body">
          <div className="ix-meta">
            <span className="muted">Discriminator</span> <CopyId value={ix.discriminator} short={false} />
          </div>
          <table className="data compact">
            <caption className="sr-only">Accounts, {flags}</caption>
            <thead>
              <tr>
                <th>Account</th>
                <th>Role</th>
                <th>Writable</th>
                <th>Signer</th>
              </tr>
            </thead>
            <tbody>
              {ix.accounts.map((a, i) => (
                <tr key={i}>
                  <td translate="no">{a.name}</td>
                  {/* Round 39: an optional account was drawn as required. */}
                  <td>
                    {a.role}
                    {a.optional && <span className="row-sub">optional</span>}
                  </td>
                  <td>{a.is_writable ? "yes" : <span className="muted">no</span>}</td>
                  <td>{a.is_signer ? "yes" : <span className="muted">no</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {ix.expected_state_changes.length > 0 && (
            <>
              <h4>Expected to</h4>
              <ul className="plain">
                {ix.expected_state_changes.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ul>
            </>
          )}
          {ix.risk_rules.length > 0 && (
            <>
              <h4>Refused unless</h4>
              <ul className="plain">
                {ix.risk_rules.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ul>
            </>
          )}
          {ix.allowed_cpis.length > 0 && (
            <>
              <h4>May call</h4>
              <ul className="chips">
                {ix.allowed_cpis.map((t) => (
                  <li key={t}>
                    <a className="chip" href={hrefFor("programs", t)}>
                      {nameOf.get(t) ?? t.slice(0, 8) + "…"}
                    </a>
                  </li>
                ))}
              </ul>
            </>
          )}
          {ix.variable_accounts && <p className="prose muted">Takes a variable number of accounts beyond those listed.</p>}
        </div>
      </details>
    </li>
  );
}

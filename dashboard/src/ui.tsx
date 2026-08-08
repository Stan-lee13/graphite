// Shared presentational primitives for the dashboard views.

export function Loading({ what }: { what: string }) {
  return <div className="state-note">Loading {what}…</div>;
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="state-note error" role="alert">
      <strong>Failed to load:</strong> {message}
      <p className="hint">
        Start the Core server (cargo run --bin graphite -- server) or check
        VITE_GRAPHITE_API. The dashboard is read-only and polls /api/*.
      </p>
    </div>
  );
}

/** Color the trust tier badge by rank (mirrors Confidence Engine P7 ordering). */
export function tierClass(tier: string): string {
  switch (tier) {
    case "BattleTested":
      return "tier tier-5";
    case "CommunityVerified":
      return "tier tier-4";
    case "SimulationValidated":
      return "tier tier-3";
    case "OfficialManifest":
      return "tier tier-2";
    case "HeuristicInferred":
      return "tier tier-1";
    default:
      return "tier tier-0";
  }
}

export function TierBadge({ tier }: { tier: string }) {
  return <span className={tierClass(tier)}>{tier}</span>;
}

/** Shorten a base58 program id for display. */
export function shortId(id: string, head = 10, tail = 6): string {
  if (id.length <= head + tail + 3) return id;
  return `${id.slice(0, head)}…${id.slice(-tail)}`;
}

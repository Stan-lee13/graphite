import { useEffect, useState } from "react";
import { GraphView } from "./views/GraphView";
import { ProtocolsView } from "./views/ProtocolsView";
import { ConfidenceView } from "./views/ConfidenceView";
import { ViolationsView } from "./views/ViolationsView";
import { RegistryView } from "./views/RegistryView";
import { setApiKey } from "./api";

const KEY_STORAGE = "graphite_api_key";

type Tab = "protocols" | "graph" | "confidence" | "violations" | "registry";

const TABS: { id: Tab; label: string }[] = [
  { id: "protocols", label: "Protocol Overview" },
  { id: "graph", label: "Semantic Graph" },
  { id: "confidence", label: "Confidence History" },
  { id: "violations", label: "Policy Violations" },
  { id: "registry", label: "Manifest Registry" },
];

interface Health {
  status: string;
  service: string;
  version: string;
}

export function App() {
  const [tab, setTab] = useState<Tab>("protocols");
  const [health, setHealth] = useState<Health | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [apiKeyInput, setApiKeyInput] = useState<string>(() => localStorage.getItem(KEY_STORAGE) ?? "");

  useEffect(() => {
    let cancelled = false;
    const check = async () => {
      try {
        const resp = await fetch("/health", { headers: { Accept: "application/json" } });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const body = (await resp.json()) as Health;
        if (!cancelled) {
          setHealth(body);
          setHealthError(null);
        }
      } catch (e) {
        if (!cancelled) setHealthError(e instanceof Error ? e.message : String(e));
      }
    };
    void check();
    const timer = setInterval(check, 10000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="logo">◈</span>
          <h1>Graphite</h1>
          <span className="tagline">Solana transaction verification · dashboard</span>
        </div>
        <div className="health">
          <label className="api-key">
            <span className="muted">API key</span>
            <input
              type="password"
              value={apiKeyInput}
              placeholder="optional — secured Core only"
              spellCheck={false}
              autoComplete="off"
              onChange={(e) => {
                setApiKeyInput(e.target.value);
                setApiKey(e.target.value);
              }}
              title="Core Bearer API key (GRAPHITE_API_KEY). Sent as Authorization: Bearer on /api/* requests. Stored locally in your browser."
            />
          </label>
          {health ? (
            <span className="health-ok">● {health.service} v{health.version} — {health.status}</span>
          ) : healthError ? (
            <span className="health-bad" title={healthError}>● Core unreachable — is the server running on :7331?</span>
          ) : (
            <span className="health-unknown">● checking…</span>
          )}
        </div>
      </header>

      <nav className="tabs" role="tablist">
        {TABS.map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={tab === t.id}
            className={tab === t.id ? "tab active" : "tab"}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </nav>

      <main className="content">
        {tab === "protocols" && <ProtocolsView />}
        {tab === "graph" && <GraphView />}
        {tab === "confidence" && <ConfidenceView />}
        {tab === "violations" && <ViolationsView />}
        {tab === "registry" && <RegistryView />}
      </main>

      <footer className="footer">
        Read-only dashboard (Constitution P4) — polls the Core /api endpoints.
        Confidence is earned, never asserted (G4): evidence signals read the
        Semantic Graph's internal accumulator.
      </footer>
    </div>
  );
}

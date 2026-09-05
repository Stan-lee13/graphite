import { useEffect, useState } from "react";
import { GraphView } from "./views/GraphView";
import { ProtocolsView } from "./views/ProtocolsView";
import { ConfidenceView } from "./views/ConfidenceView";
import { ViolationsView } from "./views/ViolationsView";
import { RegistryView } from "./views/RegistryView";
import { api, setApiKey } from "./api";
import { usePolling } from "./usePolling";

const KEY_STORAGE = "graphite_api_key";

type Tab = "protocols" | "graph" | "confidence" | "violations" | "registry";

const NAV: { id: Tab; label: string }[] = [
  { id: "protocols", label: "Protocols" },
  { id: "graph", label: "Semantic graph" },
  { id: "confidence", label: "Confidence" },
  { id: "violations", label: "Blocked" },
  { id: "registry", label: "Registry" },
];

interface Health {
  status: string;
  service: string;
  version: string;
  degraded?: boolean;
  audit?: { enabled: boolean; writes_failed?: number };
}

export function App() {
  const [tab, setTab] = useState<Tab>("protocols");
  const [health, setHealth] = useState<Health | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [apiKeyInput, setApiKeyInput] = useState<string>(
    () => localStorage.getItem(KEY_STORAGE) ?? "",
  );

  // Surfaced in the rail so a blocked-transaction count is visible from every
  // view — an operator should not have to navigate to discover something was
  // rejected.
  const violations = usePolling(() => api.policyViolations(), 5000);
  const blockedCount = violations.data?.violations.length ?? 0;

  useEffect(() => {
    let cancelled = false;
    const check = async () => {
      try {
        const resp = await fetch("/health", {
          headers: { Accept: "application/json" },
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const body = (await resp.json()) as Health;
        if (!cancelled) {
          setHealth(body);
          setHealthError(null);
        }
      } catch (e) {
        if (!cancelled) {
          setHealthError(e instanceof Error ? e.message : String(e));
          setHealth(null);
        }
      }
    };
    void check();
    const timer = setInterval(check, 10000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  // Three distinct states, not two: reachable-and-healthy, reachable-but-
  // degraded (the audit trail has failed writes — verification still works but
  // durability does not), and unreachable.
  const degraded = health?.degraded === true;
  const dotClass = healthError ? "bad" : health ? (degraded ? "bad" : "ok") : "idle";

  return (
    <div className="app">
      <aside className="rail">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true" />
          <div>
            <h1 className="brand-name">Graphite</h1>
            <span className="brand-sub">Verification gate</span>
          </div>
        </div>

        <nav className="nav" aria-label="Views">
          {NAV.map((n) => (
            <button
              key={n.id}
              className="nav-item"
              aria-current={tab === n.id}
              onClick={() => setTab(n.id)}
            >
              <span>{n.label}</span>
              {n.id === "violations" && blockedCount > 0 && (
                <span className="nav-count alert">{blockedCount}</span>
              )}
            </button>
          ))}
        </nav>

        <div className="rail-foot">
          <div>
            <div className="status">
              <span className={`dot ${dotClass}`} aria-hidden="true" />
              <span>
                {healthError
                  ? "Core unreachable"
                  : health
                    ? degraded
                      ? "Degraded"
                      : "Operational"
                    : "Connecting"}
              </span>
            </div>
            <div className="status-meta">
              {health
                ? `v${health.version}${
                    health.audit?.enabled === false ? " · no audit log" : ""
                  }`
                : healthError
                  ? "expected :7331"
                  : "…"}
            </div>
          </div>

          <div className="key-field">
            <label htmlFor="apikey">API key</label>
            <input
              id="apikey"
              type="password"
              value={apiKeyInput}
              placeholder="none (dev core)"
              spellCheck={false}
              autoComplete="off"
              onChange={(e) => {
                setApiKeyInput(e.target.value);
                setApiKey(e.target.value);
              }}
              title="Bearer key for a secured Core (GRAPHITE_API_KEY). Stored in this browser only."
            />
          </div>
        </div>
      </aside>

      <main className="main">
        {tab === "protocols" && <ProtocolsView />}
        {tab === "graph" && <GraphView />}
        {tab === "confidence" && <ConfidenceView />}
        {tab === "violations" && <ViolationsView />}
        {tab === "registry" && <RegistryView />}
      </main>
    </div>
  );
}

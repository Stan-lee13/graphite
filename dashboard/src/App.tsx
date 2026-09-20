import { useEffect, useState, type ReactNode } from "react";
import {
  Activity,
  BookMarked,
  Boxes,
  ChevronRight,
  Gauge,
  KeyRound,
  LayoutDashboard,
  ShieldBan,
  Waypoints,
} from "lucide-react";
import { OverviewView } from "./views/OverviewView";
import { GraphView } from "./views/GraphView";
import { ProtocolsView } from "./views/ProtocolsView";
import { ConfidenceView } from "./views/ConfidenceView";
import { ViolationsView } from "./views/ViolationsView";
import { RegistryView } from "./views/RegistryView";
import { api, setApiKey } from "./api";
import { usePolling } from "./usePolling";

const KEY_STORAGE = "graphite_api_key";

type Tab = "overview" | "protocols" | "graph" | "confidence" | "violations" | "registry";

interface NavItem {
  id: Tab;
  label: string;
  icon: ReactNode;
}
interface NavGroup {
  label: string;
  items: NavItem[];
}

/**
 * Grouped the way an operator thinks: what the gate knows, what it has done,
 * what it was told. Mirrors the reference console's sidebar rather than a
 * flat list of tabs.
 */
const NAV: NavGroup[] = [
  {
    label: "Monitor",
    items: [
      { id: "overview", label: "Overview", icon: <LayoutDashboard /> },
      { id: "protocols", label: "Protocols", icon: <Boxes /> },
      { id: "graph", label: "Semantic graph", icon: <Waypoints /> },
    ],
  },
  {
    label: "Audit trail",
    items: [
      { id: "confidence", label: "Confidence", icon: <Gauge /> },
      { id: "violations", label: "Blocked", icon: <ShieldBan /> },
    ],
  },
  {
    label: "Registry",
    items: [{ id: "registry", label: "Manifests", icon: <BookMarked /> }],
  },
];

const TITLE: Record<Tab, string> = {
  overview: "Overview",
  protocols: "Protocols",
  graph: "Semantic graph",
  confidence: "Confidence",
  violations: "Blocked",
  registry: "Manifests",
};

interface Health {
  status: string;
  service: string;
  version: string;
  degraded?: boolean;
  audit?: { enabled: boolean; writes_failed?: number };
}

export function App() {
  const [tab, setTab] = useState<Tab>("overview");
  const [health, setHealth] = useState<Health | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [apiKeyInput, setApiKeyInput] = useState<string>(
    () => localStorage.getItem(KEY_STORAGE) ?? "",
  );

  // Surfaced in the sidebar so a blocked-transaction count is visible from
  // every view — an operator should not have to navigate to discover
  // something was rejected.
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
  const dotClass = healthError ? "bad" : health ? (degraded ? "warn" : "ok") : "idle";
  const healthLabel = healthError
    ? "Core unreachable"
    : health
      ? degraded
        ? "Degraded"
        : "Operational"
      : "Connecting";
  const healthMeta = health
    ? `v${health.version}${health.audit?.enabled === false ? " · no audit log" : ""}`
    : healthError
      ? "expected :7331"
      : "…";

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <img
            className="brand-logo"
            src="./graphite-logo.png"
            alt=""
            width={28}
            height={28}
            aria-hidden="true"
          />
          <div className="brand-text">
            <h1 className="brand-name">Graphite</h1>
            <span className="brand-sub">Verification gate</span>
          </div>
        </div>

        <nav className="nav" aria-label="Views">
          {NAV.map((g) => (
            <div key={g.label} style={{ display: "contents" }}>
              <div className="nav-group">{g.label}</div>
              {g.items.map((n) => (
                <button
                  key={n.id}
                  className="nav-item"
                  aria-current={tab === n.id}
                  onClick={() => setTab(n.id)}
                >
                  {n.icon}
                  <span>{n.label}</span>
                  {n.id === "violations" && blockedCount > 0 && (
                    <span className="nav-count alert">{blockedCount}</span>
                  )}
                </button>
              ))}
            </div>
          ))}
        </nav>

        <div className="sidebar-foot">
          <div className="health" role="status">
            <span className={`dot ${dotClass}`} aria-hidden="true" />
            <div className="health-text">
              <span className="health-label">{healthLabel}</span>
              <span className="health-meta">{healthMeta}</span>
            </div>
          </div>

          <div className="key-field">
            <label htmlFor="apikey">
              <KeyRound aria-hidden="true" />
              API key
            </label>
            <div className="key-wrap">
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
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <div className="crumbs" aria-label="Breadcrumb">
            <span>Graphite</span>
            <ChevronRight aria-hidden="true" />
            <span className="here">{TITLE[tab]}</span>
          </div>
          <div className="topbar-right">
            {health && !healthError && (
              <span className="live" title="Polling every 5s">
                <span className="dot" aria-hidden="true" />
                live
              </span>
            )}
            <span className={`pill ${dotClass === "ok" ? "ok" : dotClass === "bad" ? "bad" : dotClass === "warn" ? "warn" : ""}`}>
              <Activity aria-hidden="true" />
              {healthLabel}
            </span>
            {health && (
              <span className="pill mono" title={health.service}>
                v{health.version}
              </span>
            )}
          </div>
        </header>

        <main className="content">
          {tab === "overview" && <OverviewView onNavigate={(t) => setTab(t)} />}
          {tab === "protocols" && <ProtocolsView />}
          {tab === "graph" && <GraphView />}
          {tab === "confidence" && <ConfidenceView />}
          {tab === "violations" && <ViolationsView />}
          {tab === "registry" && <RegistryView />}
        </main>
      </div>
    </div>
  );
}

export type { Tab };

import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  Activity,
  BookMarked,
  Boxes,
  Cable,
  Ellipsis,
  LayoutGrid,
  ListChecks,
  Search,
  ShieldBan,
  Waypoints,
  X,
} from "lucide-react";
import { api, getConnection, onConnectionChange, type Health } from "./api";
import { hrefFor, navigate, useRoute, type View } from "./router";
import { useLayout, usePolling } from "./usePolling";
import { CommandPalette } from "./CommandPalette";
import { OverviewView } from "./views/OverviewView";
import { ProgramsView } from "./views/ProgramsView";
import { GraphView } from "./views/GraphView";
import { VerificationsView } from "./views/VerificationsView";
import { BlockedView } from "./views/BlockedView";
import { RegistryView } from "./views/RegistryView";
import { SystemView } from "./views/SystemView";
import { ConnectView } from "./views/ConnectView";

interface NavItem {
  id: View;
  label: string;
  icon: ReactNode;
}

/** Sidebar, grouped the way an operator asks questions. */
const NAV: { label: string; items: NavItem[] }[] = [
  {
    label: "Gate",
    items: [
      { id: "overview", label: "Overview", icon: <LayoutGrid /> },
      { id: "programs", label: "Programs", icon: <Boxes /> },
      { id: "graph", label: "Call graph", icon: <Waypoints /> },
    ],
  },
  {
    label: "Trail",
    items: [
      { id: "verifications", label: "Verifications", icon: <ListChecks /> },
      { id: "blocked", label: "Blocked", icon: <ShieldBan /> },
      { id: "registry", label: "Registry", icon: <BookMarked /> },
    ],
  },
  {
    label: "Core",
    items: [
      { id: "system", label: "System", icon: <Activity /> },
      { id: "connect", label: "Connection", icon: <Cable /> },
    ],
  },
];

/** The five destinations that earn a thumb on a phone. Everything else is
 *  one tap away under More. */
const PHONE_TABS: NavItem[] = [
  { id: "overview", label: "Overview", icon: <LayoutGrid /> },
  { id: "programs", label: "Programs", icon: <Boxes /> },
  { id: "verifications", label: "Trail", icon: <ListChecks /> },
  { id: "blocked", label: "Blocked", icon: <ShieldBan /> },
];
const PHONE_MORE: NavItem[] = [
  { id: "graph", label: "Call graph", icon: <Waypoints /> },
  { id: "registry", label: "Registry", icon: <BookMarked /> },
  { id: "system", label: "System", icon: <Activity /> },
  { id: "connect", label: "Connection", icon: <Cable /> },
];

export const TITLE: Record<View, string> = {
  overview: "Overview",
  programs: "Programs",
  graph: "Call graph",
  verifications: "Verifications",
  blocked: "Blocked",
  registry: "Registry",
  system: "System",
  connect: "Connection",
};

export type CoreState = "ok" | "degraded" | "unauthorized" | "down" | "connecting";

export function App() {
  const route = useRoute();
  const layout = useLayout();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [moreOpen, setMoreOpen] = useState(false);
  const [conn, setConn] = useState(getConnection);
  useEffect(() => onConnectionChange(() => setConn(getConnection())), []);

  // /health needs no key, so it separates "down" from "wrong key". The
  // blocked list is the cheapest key-guarded poll, and its error kind is the
  // verdict on the key from every view at once.
  const health = usePolling<Health>(() => api.health(), 10000);
  const blocked = usePolling(() => api.policyViolations(), 5000);
  const blockedCount = blocked.data?.violations.length ?? 0;

  const core: CoreState = health.error
    ? "down"
    : !health.data
      ? "connecting"
      : blocked.error?.kind === "unauthorized"
        ? "unauthorized"
        : health.data.degraded
          ? "degraded"
          : "ok";

  // First run with nothing configured and nothing answering: go straight to
  // the connection screen rather than to seven empty panels.
  useEffect(() => {
    if (core === "down" && !conn.base && route.view !== "connect" && !sessionStorage.getItem("graphite.sawConnect")) {
      sessionStorage.setItem("graphite.sawConnect", "1");
      navigate("connect");
    }
  }, [core, conn.base, route.view]);

  useEffect(() => {
    document.title = `${TITLE[route.view]} — Graphite`;
  }, [route.view]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Close the More sheet whenever the route moves on.
  useEffect(() => setMoreOpen(false), [route.view]);

  const page = useMemo(() => {
    switch (route.view) {
      case "overview":
        return <OverviewView />;
      case "programs":
        return <ProgramsView selected={route.program} />;
      case "graph":
        return <GraphView selected={route.program} />;
      case "verifications":
        return <VerificationsView />;
      case "blocked":
        return <BlockedView />;
      case "registry":
        return <RegistryView />;
      case "system":
        return <SystemView />;
      case "connect":
        return <ConnectView core={core} />;
    }
  }, [route.view, route.program, core]);

  const status = <CoreStatus core={core} health={health.data} base={conn.base} />;

  return (
    <div className={`app ${layout}`}>
      <a className="skip" href="#main">
        Skip to content
      </a>

      {layout === "phone" ? (
        <header className="phone-bar">
          <a className="brand" href={hrefFor("overview")} aria-label="Graphite, overview">
            <span className="brand-tile" aria-hidden="true">
              <img src="./graphite-logo.png" alt="" width={30} height={30} />
            </span>
            <span className="brand-name">Graphite</span>
          </a>
          <div className="phone-bar-right">
            <StatusDot core={core} />
            <button type="button" className="icon-btn" aria-label="Search" onClick={() => setPaletteOpen(true)}>
              <Search aria-hidden="true" />
            </button>
          </div>
        </header>
      ) : (
        <aside className="sidebar" aria-label="Navigation">
          <a className="brand" href={hrefFor("overview")} aria-label="Graphite, overview">
            <span className="brand-tile" aria-hidden="true">
              <img src="./graphite-logo.png" alt="" width={36} height={36} />
            </span>
            <span className="brand-text">
              <span className="brand-name">Graphite</span>
              <span className="brand-sub">Console</span>
            </span>
          </a>

          <button type="button" className="search-btn" aria-label="Search" onClick={() => setPaletteOpen(true)}>
            <Search aria-hidden="true" />
            <span>Search</span>
            <kbd aria-hidden="true">{isMac() ? "⌘" : "Ctrl"} K</kbd>
          </button>

          <nav className="nav">
            {NAV.map((g) => (
              <div className="nav-group" key={g.label}>
                <div className="nav-group-label">{g.label}</div>
                {g.items.map((n) => (
                  <a
                    key={n.id}
                    href={hrefFor(n.id)}
                    className="nav-item"
                    aria-current={route.view === n.id ? "page" : undefined}
                    title={n.label}
                  >
                    {n.icon}
                    <span className="nav-label">{n.label}</span>
                    {n.id === "blocked" && blockedCount > 0 && (
                      <span className="nav-count">{blockedCount}</span>
                    )}
                  </a>
                ))}
              </div>
            ))}
          </nav>

          <div className="sidebar-foot">{status}</div>
        </aside>
      )}

      <div className="main">
        <main id="main" className="content" tabIndex={-1}>
          {core === "unauthorized" && route.view !== "connect" && (
            <div className="banner warn" role="status">
              <span>The Core rejected the key stored in this browser. Every panel below will stay empty until it is fixed.</span>
              <a className="btn small" href={hrefFor("connect")}>
                Fix the key
              </a>
            </div>
          )}
          {page}
        </main>
      </div>

      {layout === "phone" && (
        <>
          <nav className="tabbar" aria-label="Primary">
            {PHONE_TABS.map((t) => (
              <a
                key={t.id}
                href={hrefFor(t.id)}
                className="tab"
                aria-current={route.view === t.id ? "page" : undefined}
              >
                <span className="tab-icon">
                  {t.icon}
                  {t.id === "blocked" && blockedCount > 0 && <span className="tab-dot" aria-hidden="true" />}
                </span>
                <span>{t.label}</span>
              </a>
            ))}
            <button
              type="button"
              className="tab"
              aria-current={PHONE_MORE.some((m) => m.id === route.view) ? "page" : undefined}
              aria-expanded={moreOpen}
              onClick={() => setMoreOpen(true)}
            >
              <span className="tab-icon">
                <Ellipsis />
              </span>
              <span>More</span>
            </button>
          </nav>

          {moreOpen && (
            <>
              <div className="scrim" onClick={() => setMoreOpen(false)} aria-hidden="true" />
              <div className="sheet" role="dialog" aria-label="More">
                <div className="sheet-grab" aria-hidden="true" />
                <div className="sheet-head">
                  <span>More</span>
                  <button type="button" className="icon-btn" aria-label="Close" onClick={() => setMoreOpen(false)}>
                    <X aria-hidden="true" />
                  </button>
                </div>
                <div className="sheet-list">
                  {PHONE_MORE.map((m) => (
                    <a key={m.id} href={hrefFor(m.id)} className="sheet-item" aria-current={route.view === m.id ? "page" : undefined}>
                      {m.icon}
                      <span>{m.label}</span>
                    </a>
                  ))}
                </div>
                <div className="sheet-foot">{status}</div>
              </div>
            </>
          )}
        </>
      )}

      {paletteOpen && <CommandPalette onClose={() => setPaletteOpen(false)} />}
    </div>
  );
}

function isMac(): boolean {
  return /Mac|iPhone|iPad/.test(navigator.platform);
}

function StatusDot({ core }: { core: CoreState }) {
  return <i className={`dot ${core}`} aria-label={coreLabel(core)} role="img" />;
}

export function coreLabel(core: CoreState): string {
  switch (core) {
    case "ok":
      return "Core operational";
    case "degraded":
      return "Core degraded";
    case "unauthorized":
      return "Key rejected";
    case "down":
      return "Core unreachable";
    case "connecting":
      return "Connecting…";
  }
}

/** The connection, as a small card that is also the way to the Connect screen. */
function CoreStatus({ core, health, base }: { core: CoreState; health: Health | null; base: string }) {
  const where = base ? base.replace(/^https?:\/\//, "") : "this origin";
  const sub =
    core === "ok" || core === "degraded"
      ? `v${health?.version ?? "?"}, ${where}${health?.audit?.enabled === false ? ", no audit log" : ""}`
      : core === "unauthorized"
        ? "the key in this browser is wrong"
        : core === "down"
          ? where
          : "…";
  return (
    <a className="core-status" href={hrefFor("connect")} title="Connection settings">
      <StatusDot core={core} />
      <span className="core-status-text">
        <span className="core-status-label">{coreLabel(core)}</span>
        <span className="core-status-sub" translate="no">
          {sub}
        </span>
      </span>
    </a>
  );
}

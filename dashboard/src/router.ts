// Hash routing. The URL carries the view and the selected program, so a link
// to "#/programs/JUP6…" opens exactly that drawer, and the back button does
// what a person expects. No dependency: the console has seven routes.

import { useEffect, useState } from "react";

export type View =
  | "overview"
  | "programs"
  | "graph"
  | "verifications"
  | "blocked"
  | "registry"
  | "system"
  | "connect";

export interface Route {
  view: View;
  /** `#/programs/<id>` or `#/graph/<id>`: the program open in the detail pane. */
  program?: string;
}

const VIEWS: ReadonlySet<string> = new Set<View>([
  "overview",
  "programs",
  "graph",
  "verifications",
  "blocked",
  "registry",
  "system",
  "connect",
]);

export function parseHash(hash: string): Route {
  const parts = hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  const view = parts[0] ?? "overview";
  if (!VIEWS.has(view)) return { view: "overview" };
  const program = parts[1] ? decodeURIComponent(parts[1]) : undefined;
  return program ? { view: view as View, program } : { view: view as View };
}

export function hrefFor(view: View, program?: string): string {
  return program ? `#/${view}/${encodeURIComponent(program)}` : `#/${view}`;
}

export function navigate(view: View, program?: string): void {
  const next = hrefFor(view, program);
  if (window.location.hash !== next) window.location.hash = next;
}

export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(() => parseHash(window.location.hash));
  useEffect(() => {
    const on = () => setRoute(parseHash(window.location.hash));
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return route;
}

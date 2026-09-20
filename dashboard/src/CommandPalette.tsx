// ⌘K. Views and programs in one list: type a name or the start of a program
// ID, press Enter, land there. The program list comes from the same graph
// poll every view uses, so the palette never knows a program the console
// does not.

import { useEffect, useMemo, useRef, useState } from "react";
import { Boxes, CornerDownLeft, Search } from "lucide-react";
import { api } from "./api";
import { hrefFor, navigate, type View } from "./router";
import { usePolling } from "./usePolling";
import { TITLE } from "./App";
import { TierBadge, shortId } from "./ui";

interface Item {
  key: string;
  label: string;
  hint?: string;
  view: View;
  program?: string;
  tier?: string;
}

const VIEW_ORDER: View[] = ["overview", "programs", "graph", "verifications", "blocked", "registry", "system", "connect"];

export function CommandPalette({ onClose }: { onClose: () => void }) {
  const [q, setQ] = useState("");
  const [cursor, setCursor] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const graph = usePolling(() => api.graph(), 30000);

  useEffect(() => {
    input.current?.focus();
  }, []);

  const items = useMemo<Item[]>(() => {
    const needle = q.trim().toLowerCase();
    const views: Item[] = VIEW_ORDER.map((v) => ({ key: `v:${v}`, label: TITLE[v], hint: "Go to", view: v }));
    const programs: Item[] = (graph.data?.nodes ?? []).map((n) => ({
      key: `p:${n.program_id}`,
      label: n.name,
      hint: shortId(n.program_id, 8, 6),
      view: "programs",
      program: n.program_id,
      tier: n.trust_tier,
    }));
    if (!needle) return [...views, ...programs.slice(0, 8)];
    const hit = (s: string) => s.toLowerCase().includes(needle);
    return [
      ...views.filter((v) => hit(v.label)),
      ...programs.filter((p) => hit(p.label) || p.program!.toLowerCase().startsWith(needle)),
    ].slice(0, 14);
  }, [q, graph.data]);

  useEffect(() => setCursor(0), [q]);

  const go = (it: Item) => {
    navigate(it.view, it.program);
    onClose();
  };

  return (
    <>
      <div className="scrim" onClick={onClose} aria-hidden="true" />
      <div className="palette" role="dialog" aria-modal="true" aria-label="Search">
        <div className="palette-input">
          <Search aria-hidden="true" />
          <input
            ref={input}
            type="search"
            name="q"
            value={q}
            placeholder="Search views and programs…"
            autoComplete="off"
            spellCheck={false}
            aria-label="Search views and programs"
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape") onClose();
              if (e.key === "ArrowDown") {
                e.preventDefault();
                setCursor((c) => Math.min(items.length - 1, c + 1));
              }
              if (e.key === "ArrowUp") {
                e.preventDefault();
                setCursor((c) => Math.max(0, c - 1));
              }
              if (e.key === "Enter" && items[cursor]) go(items[cursor]);
            }}
          />
          <kbd>Esc</kbd>
        </div>
        <ul className="palette-list" role="listbox">
          {items.length === 0 && <li className="palette-empty">Nothing matches “{q}”.</li>}
          {items.map((it, i) => (
            <li key={it.key} role="option" aria-selected={i === cursor}>
              <a
                href={hrefFor(it.view, it.program)}
                className={i === cursor ? "palette-item on" : "palette-item"}
                onMouseEnter={() => setCursor(i)}
                onClick={(e) => {
                  e.preventDefault();
                  go(it);
                }}
              >
                {it.program ? <Boxes aria-hidden="true" /> : <span className="palette-go">{it.hint}</span>}
                <span className="palette-label">{it.label}</span>
                {it.program && (
                  <span className="palette-hint" translate="no">
                    {it.hint}
                  </span>
                )}
                {it.tier && <TierBadge tier={it.tier} compact />}
                {i === cursor && <CornerDownLeft className="palette-enter" aria-hidden="true" />}
              </a>
            </li>
          ))}
        </ul>
      </div>
    </>
  );
}

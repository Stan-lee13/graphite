import { useEffect, useRef, useState } from "react";
import { ApiError, onConnectionChange, toApiError } from "./api";

export interface Polled<T> {
  data: T | null;
  error: ApiError | null;
  loading: boolean;
  /** When the last successful fetch landed, for "updated 4s ago". */
  updatedAt: number | null;
}

/**
 * Poll a data source every `intervalMs`, tracking loading/error state.
 * Real-time push is deferred to Phase 3 — this is the deliberate polling
 * design. Errors are surfaced (never silently swallowed) and the last good
 * payload is preserved across transient failures. A change of Core or key
 * restarts the loop immediately so the operator sees the effect of a new
 * setting without waiting out the interval.
 */
export function usePolling<T>(loader: () => Promise<T>, intervalMs = 5000): Polled<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(true);
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);
  const [epoch, setEpoch] = useState(0);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;

  useEffect(() => onConnectionChange(() => setEpoch((e) => e + 1)), []);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    async function tick() {
      try {
        const value = await loaderRef.current();
        if (!cancelled) {
          setData(value);
          setError(null);
          setUpdatedAt(Date.now());
        }
      } catch (e) {
        if (!cancelled) setError(toApiError(e, "poll"));
      } finally {
        if (!cancelled) {
          setLoading(false);
          // Back off while the page is hidden: nobody is looking, and a
          // background tab hammering a Core is a poor neighbour.
          const wait = document.visibilityState === "hidden" ? intervalMs * 6 : intervalMs;
          timer = setTimeout(tick, wait);
        }
      }
    }

    setLoading(true);
    void tick();
    return () => {
      cancelled = true;
      if (timer !== undefined) clearTimeout(timer);
    };
  }, [intervalMs, epoch]);

  return { data, error, loading, updatedAt };
}

/** Which anatomy the shell renders. Mobile and desktop are different layouts,
 *  not one layout at two widths, so this is a discrete mode. */
export type Layout = "phone" | "tablet" | "desktop";

export function useLayout(): Layout {
  const q = () =>
    window.matchMedia("(max-width: 767px)").matches
      ? "phone"
      : window.matchMedia("(max-width: 1099px)").matches
        ? "tablet"
        : "desktop";
  const [layout, setLayout] = useState<Layout>(q);
  useEffect(() => {
    const phone = window.matchMedia("(max-width: 767px)");
    const tablet = window.matchMedia("(max-width: 1099px)");
    const on = () => setLayout(q());
    phone.addEventListener("change", on);
    tablet.addEventListener("change", on);
    return () => {
      phone.removeEventListener("change", on);
      tablet.removeEventListener("change", on);
    };
  }, []);
  return layout;
}

/** `prefers-reduced-motion`, so JS-driven motion can stand down too. */
export function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(
    () => window.matchMedia("(prefers-reduced-motion: reduce)").matches,
  );
  useEffect(() => {
    const m = window.matchMedia("(prefers-reduced-motion: reduce)");
    const on = () => setReduced(m.matches);
    m.addEventListener("change", on);
    return () => m.removeEventListener("change", on);
  }, []);
  return reduced;
}

// Where the console may send the operator key. No imports and no Vite env, so
// it runs under Node for its tests (transport.test.ts, `tsx --test`).
//
// Round 19 (F-19-C6): the console accepted any http:// Core address and sent
// `Authorization: Bearer <key>` to it. On anything but the local machine that
// puts the operator key on the wire in the clear, and lets anyone on the path
// rewrite what the console shows. https:// is always accepted; http:// only
// when the host is loopback (localhost, 127.0.0.0/8, [::1]). An empty base
// means "same origin", so the page's own origin is what gets checked.

/** Canonical loopback hostnames only; the URL parser has already normalised
 *  `127.1` to `127.0.0.1` and bracketed IPv6. */
export function isLoopbackHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (h === "localhost" || h === "[::1]") return true;
  const m = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  return m !== null && m.slice(1).every((o) => Number(o) <= 255);
}

/**
 * Why the console must not talk to `base`, or null when it may. `pageOrigin`
 * is `window.location.origin`, used when `base` is empty (same origin).
 */
export function insecureBaseReason(base: string, pageOrigin: string): string | null {
  let url: URL;
  try {
    url = new URL(base || pageOrigin);
  } catch {
    // Round 29 (audit 2026-10-20, D7): an empty base used to produce
    // `"" is not a URL`, which names nothing the operator typed. An empty
    // base means "this page's origin"; when that is not a web origin (a page
    // opened from file:// has the origin "null") say so.
    if (!base) {
      return (
        `This page has no web origin (${pageOrigin || "none"}), so "same origin" names no Core. ` +
        "Enter the Core's origin, e.g. https://graphite.example or http://127.0.0.1:7331."
      );
    }
    return `"${base}" is not a URL. Enter the Core's origin, e.g. https://graphite.example or http://127.0.0.1:7331.`;
  }
  if (url.protocol === "https:") return null;
  if (url.protocol === "http:") {
    if (isLoopbackHost(url.hostname)) return null;
    return (
      `${url.origin} is plain http:// to another machine: the API key and everything the Core ` +
      "returns would cross the network unencrypted. Serve the Core over https://, or use http:// " +
      "only on this machine (localhost, 127.0.0.1, [::1])."
    );
  }
  return `${url.protocol} is not a Core address. Use https://, or http:// on this machine.`;
}

/**
 * `fetch` for every request the console makes to the Core: never follows a
 * redirect.
 *
 * A5-04 (2026-09-29 audit): the transport rule above is checked against the
 * configured base, and `fetch` follows redirects by default — a Core or a
 * proxy answering 307 to an http:// URL took the request, and what the
 * console then displayed, somewhere the rule never looked. With
 * `redirect: "error"` a redirect is a failed request and its target is not
 * contacted.
 */
export async function fetchFromCore(
  url: string,
  headers: Record<string, string>,
  timeoutMs: number = REQUEST_TIMEOUT_MS,
): Promise<CoreResponse> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const resp = await fetch(url, { headers, redirect: "error", signal: ctl.signal });
    // The body is read under the same deadline: a Core that sends its
    // headers and then stalls mid-body is as stuck as one that never answers.
    const text = await resp.text();
    return { ok: resp.ok, status: resp.status, text };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Round 29 (audit 2026-10-20, D3): no request had a deadline. `usePolling`
 * schedules the next tick only after the current one settles, so one request
 * the Core (or a proxy) accepted and never answered stopped that view's
 * polling for good, silently, while the last payload stayed on screen as if
 * it were current. Every request now aborts after this long, headers and body
 * together, and the abort surfaces as "no response".
 */
export const REQUEST_TIMEOUT_MS = 15_000;

/** What the console keeps of a Core response: the status and the whole body. */
export interface CoreResponse {
  ok: boolean;
  status: number;
  text: string;
}

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
 * The plain-http loopback hosts the built console's Content-Security-Policy
 * can name in `connect-src` (csp.ts LOOPBACK_HTTP). Round 30: a CSP host
 * source cannot be an IPv6 literal (Chrome drops `http://[::1]:*` as invalid)
 * nor a range (127.0.0.0/8), so a Core at http://[::1] or http://127.0.0.2
 * passed this rule and was then blocked by the CSP — reported as "No
 * response from the Core" with advice about CORS that could not help. Those
 * addresses are refused here, before sending, with the reason.
 */
export const CSP_LOOPBACK_HOSTS: readonly string[] = ["localhost", "127.0.0.1"];

/**
 * Why the console must not talk to `base`, or null when it may. `pageOrigin`
 * is `window.location.origin`, used when `base` is empty (same origin).
 * `buildOrigin` is the origin of a build-time `VITE_GRAPHITE_API`, which the
 * CSP names explicitly.
 */
export function insecureBaseReason(base: string, pageOrigin: string, buildOrigin: string | null = null): string | null {
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
    if (isLoopbackHost(url.hostname)) {
      // Same origin is the CSP's 'self', whatever the address.
      if (!base || CSP_LOOPBACK_HOSTS.includes(url.hostname.toLowerCase()) || url.origin === buildOrigin) return null;
      return (
        `${url.origin} is on this machine, but the console's Content-Security-Policy can only name ` +
        "http://localhost and http://127.0.0.1 for a plain-http Core. Use one of those (with the same port)."
      );
    }
    return (
      `${url.origin} is plain http:// to another machine: the API key and everything the Core ` +
      "returns would cross the network unencrypted. Serve the Core over https://, or use http:// " +
      "only on this machine (localhost, 127.0.0.1)."
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
  maxBytes: number = MAX_RESPONSE_BYTES,
): Promise<CoreResponse> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const resp = await fetch(url, { headers, redirect: "error", signal: ctl.signal });
    // The body is read under the same deadline: a Core that sends its
    // headers and then stalls mid-body is as stuck as one that never answers.
    // Round 38 (G2-6): and up to a bound, declared or streamed.
    const text = await readBounded(resp, maxBytes, ctl);
    return { ok: resp.ok, status: resp.status, text };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * The most bytes one Core answer may carry (Round 38, G2-6): the bound the
 * guard holds its RPC answers to, and the Core its own (32 MiB). The body
 * was read with `resp.text()`, so whatever answered for the Core could hand
 * the console a body of any size and hold the tab's memory with it.
 */
export const MAX_RESPONSE_BYTES = 32 * 1024 * 1024;

/** A Core answer larger than `MAX_RESPONSE_BYTES`: not read, the request failed. */
export class ResponseTooLarge extends Error {
  constructor(how: string, max: number) {
    super(`The Core's answer is over the ${max}-byte bound (${how}); it was not read.`);
    this.name = "ResponseTooLarge";
  }
}

/** The body as text, refused past `max` bytes: a declared length first, then as it streams. */
async function readBounded(resp: Response, max: number, ctl: AbortController): Promise<string> {
  const declared = resp.headers.get("content-length");
  if (declared !== null && Number(declared) > max) {
    ctl.abort();
    throw new ResponseTooLarge(`it declares ${declared} bytes`, max);
  }
  if (!resp.body) return "";
  const reader = resp.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => {});
      ctl.abort();
      throw new ResponseTooLarge("as it streamed", max);
    }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    all.set(c, at);
    at += c.byteLength;
  }
  return new TextDecoder().decode(all);
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

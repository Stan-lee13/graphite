// Where the console may send the operator key. No imports and no Vite env, so
// it runs under plain Node for its tests (transport.test.ts).
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

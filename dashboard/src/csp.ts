// The Content-Security-Policy the production build carries in index.html.
// No imports, so vite.config.ts can load it and Node can test it
// (csp.test.ts, `tsx --test`).
//
// Round 29 (audit 2026-10-20, D6): the console had no CSP, and the operator
// key sits in Web Storage where any script running on this origin can read
// it. The policy below lets only the console's own bundle run (no inline
// script, no eval, no third-party script), loads styles, fonts and images
// only from the console's own origin, and forbids plugins, framing targets
// for forms and <base> rewriting.
//
// connect-src cannot name "the Core": the Core's address is chosen at run
// time on the Connection screen. It allows exactly what transport.ts allows
// the console to talk to — any https:// origin and plain http:// on
// loopback — plus the console's own origin and the build-time default Core.
// A CSP cannot express 127.0.0.0/8, so a Core on 127.0.0.2 and up must be
// addressed as 127.0.0.1, localhost or over https://.
//
// The policy is injected at build time only: Vite's dev server serves an
// inline React-refresh preamble and injects CSS through <style> tags, both
// of which this policy (correctly) forbids.

/**
 * Loopback origins a plain-http Core may use (transport.ts
 * CSP_LOOPBACK_HOSTS). Round 30: `http://[::1]:*` stood here; a CSP host
 * source cannot be an IPv6 literal, and Chrome ignored it with a console
 * error on every load, so it never allowed anything. transport.ts now
 * refuses http://[::1] with that reason instead.
 */
export const LOOPBACK_HTTP = ["http://localhost:*", "http://127.0.0.1:*"];

/** The origin of a build-time `VITE_GRAPHITE_API`, if it is an http(s) URL. */
export function originOf(raw: string | undefined): string | null {
  if (!raw) return null;
  try {
    const u = new URL(raw);
    return u.protocol === "http:" || u.protocol === "https:" ? u.origin : null;
  } catch {
    return null;
  }
}

/**
 * Response headers for whatever serves the built console. Round 30: a CSP
 * delivered in a <meta> tag cannot carry `frame-ancestors` (browsers ignore
 * it there), so nothing stopped another site framing the console — which
 * holds the operator key — and nothing set nosniff or a referrer policy.
 * `vite preview` serves these (vite.config.ts); a production static host must
 * be configured with the same set (README "Serving it"). The header CSP is
 * the meta policy plus `frame-ancestors 'none'`.
 */
export function securityHeaders(buildApi?: string): Record<string, string> {
  return {
    "Content-Security-Policy": `${contentSecurityPolicy(buildApi)}; frame-ancestors 'none'`,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  };
}

export function contentSecurityPolicy(buildApi?: string): string {
  const connect = ["'self'", "https:", ...LOOPBACK_HTTP];
  const built = originOf(buildApi);
  if (built && !connect.includes(built) && !built.startsWith("https:")) connect.push(built);
  return [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "font-src 'self' data:",
    "img-src 'self' data:",
    `connect-src ${connect.join(" ")}`,
    "manifest-src 'self'",
    "base-uri 'none'",
    "form-action 'none'",
    "object-src 'none'",
  ].join("; ");
}

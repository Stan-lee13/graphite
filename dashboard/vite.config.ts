import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { contentSecurityPolicy } from "./src/csp";

// The dashboard polls the Graphite Core server's read-only /api endpoints.
// In dev, Vite proxies the Core's read-only routes so the browser never needs
// CORS; in production the built assets are served by any static host and the
// Core address is set at runtime on the Connection screen (or pre-set at
// build time with VITE_GRAPHITE_API; default: same origin).
const apiTarget = process.env.VITE_GRAPHITE_PROXY ?? "http://localhost:7331";

/**
 * Round 29 (audit 2026-10-20, D6): the built index.html carries a strict
 * Content-Security-Policy (src/csp.ts). Build only: the dev server needs an
 * inline React-refresh preamble and injected <style> tags.
 */
function contentSecurityPolicyMeta(): Plugin {
  return {
    name: "graphite-csp",
    apply: "build",
    transformIndexHtml: {
      order: "post",
      handler: () => [
        {
          tag: "meta",
          attrs: {
            "http-equiv": "Content-Security-Policy",
            content: contentSecurityPolicy(process.env.VITE_GRAPHITE_API),
          },
          injectTo: "head-prepend",
        },
      ],
    },
  };
}

export default defineConfig({
  plugins: [react(), contentSecurityPolicyMeta()],
  // Relative asset base so the built console can be served from any subpath
  // (https://host/graphite/), not only from a server's root — the default "/"
  // emits absolute /assets/... URLs that 404 under a subpath. Round 29
  // (audit 2026-10-20, D7): this comment used to promise that the built
  // index.html also works opened from file://. It does not: browsers refuse
  // module scripts from file:// origins, and a file:// page has no origin
  // for "same origin" to mean. Serve dist/ over http(s).
  base: "./",
  server: {
    // PORT lets a launcher pick a free port; 5173 otherwise.
    port: Number(process.env.PORT) || 5173,
    proxy: {
      "/api": { target: apiTarget, changeOrigin: true },
      "/health": { target: apiTarget, changeOrigin: true },
      "/metrics": { target: apiTarget, changeOrigin: true },
      "/manifests": { target: apiTarget, changeOrigin: true },
    },
  },
  build: {
    outDir: "dist",
    // Round 29 (D6): production builds no longer ship source maps (they
    // published the full TypeScript source next to the bundle). Set
    // GRAPHITE_DASHBOARD_SOURCEMAP=1 for a local debugging build.
    sourcemap: process.env.GRAPHITE_DASHBOARD_SOURCEMAP === "1",
  },
});

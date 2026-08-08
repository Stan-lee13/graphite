import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dashboard polls the Graphite Core server's read-only /api endpoints.
// In dev, Vite proxies /api and /health to Core so the browser never needs
// CORS; in production the built assets are served by any static host and the
// API base is configured via VITE_GRAPHITE_API (default same-origin /api).
const apiTarget = process.env.VITE_GRAPHITE_PROXY ?? "http://localhost:7331";

export default defineConfig({
  plugins: [react()],
  // Relative asset base so the BUILT index.html works when opened via
  // file:// or served from any subpath — the default "/" emits absolute
  // /assets/... URLs that render a blank page outside a root-mounted server.
  base: "./",
  server: {
    port: 5173,
    proxy: {
      "/api": { target: apiTarget, changeOrigin: true },
      "/health": { target: apiTarget, changeOrigin: true },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});

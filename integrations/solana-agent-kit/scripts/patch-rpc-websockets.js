/**
 * Postinstall patch: Make rpc-websockets@10 backward-compatible with deep imports.
 *
 * Problem: rpc-websockets@10 added an "exports" field that blocks deep imports
 * (e.g., 'rpc-websockets/dist/lib/client'). Old @solana/web3.js versions (v1.77-v1.92)
 * bundled in jito-ts and @drift-labs use these deep imports.
 *
 * Fix: Copy dist/lib from rpc-websockets@7.11.2 (which has the files) and add
 * the deep import paths to the exports field in v10's package.json.
 */
const fs = require("fs");
const path = require("path");

const rwDir = path.join(__dirname, "..", "node_modules", "rpc-websockets");
const rwPkg = path.join(rwDir, "package.json");

if (!fs.existsSync(rwPkg)) {
  console.log("[patch-rpc-websockets] rpc-websockets not found, skipping");
  process.exit(0);
}

// 1. Check if dist/lib already exists
const distLib = path.join(rwDir, "dist", "lib");
if (!fs.existsSync(distLib)) {
  // Find a v7.x copy to source the files from
  const candidates = [
    path.join(__dirname, "..", "node_modules", "jito-ts", "node_modules", "rpc-websockets", "dist", "lib"),
  ];
  function findRpcLib(dir, depth) {
    if (depth > 5) return null;
    const candidate = path.join(dir, "rpc-websockets", "dist", "lib");
    if (fs.existsSync(path.join(candidate, "client.cjs"))) return candidate;
    try {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (entry.isDirectory() && entry.name === "node_modules") {
          const found = findRpcLib(path.join(dir, entry.name), depth + 1);
          if (found) return found;
        }
      }
    } catch {}
    return null;
  }
  const searchRoot = path.join(__dirname, "..", "node_modules");
  const source = candidates.find(function(c) { return fs.existsSync(path.join(c, "client.cjs")); }) || findRpcLib(searchRoot, 0);
  if (source) {
    fs.mkdirSync(distLib, { recursive: true });
    fs.mkdirSync(path.join(distLib, "client"), { recursive: true });
    for (const file of fs.readdirSync(source)) {
      fs.copyFileSync(path.join(source, file), path.join(distLib, file));
    }
    const clientSource = path.join(source, "client");
    if (fs.existsSync(clientSource)) {
      for (const file of fs.readdirSync(clientSource)) {
        fs.copyFileSync(path.join(clientSource, file), path.join(distLib, "client", file));
      }
    }
    console.log("[patch-rpc-websockets] Copied dist/lib from v7.x");
  } else {
    console.warn("[patch-rpc-websockets] Could not find rpc-websockets v7.x to copy dist/lib from");
  }
}

// 2. Patch the exports field
const pkg = JSON.parse(fs.readFileSync(rwPkg, "utf-8"));
if (pkg.exports && pkg.exports["./dist/lib/client"]) {
  console.log("[patch-rpc-websockets] Already patched, skipping");
  process.exit(0);
}

// Restructure exports: move top-level condition keys under "."
const oldExports = pkg.exports;
const newExports = { ".": oldExports };

// Add deep import paths
const deepPaths = {
  "./dist/lib/client": "./dist/lib/client.cjs",
  "./dist/lib/client.cjs": "./dist/lib/client.cjs",
  "./dist/lib/client/client.types": "./dist/lib/client/client.types.cjs",
  "./dist/lib/client/client.types.cjs": "./dist/lib/client/client.types.cjs",
  "./dist/lib/client/websocket": "./dist/lib/client/websocket.cjs",
  "./dist/lib/client/websocket.cjs": "./dist/lib/client/websocket.cjs",
  "./dist/lib/client/websocket.browser": "./dist/lib/client/websocket.browser.cjs",
  "./dist/lib/client/websocket.browser.cjs": "./dist/lib/client/websocket.browser.cjs",
  "./dist/lib/server": "./dist/lib/server.cjs",
  "./dist/lib/server.cjs": "./dist/lib/server.cjs",
  "./dist/lib/utils": "./dist/lib/utils.cjs",
  "./dist/lib/utils.cjs": "./dist/lib/utils.cjs",
};

Object.assign(newExports, deepPaths);
pkg.exports = newExports;

fs.writeFileSync(rwPkg, JSON.stringify(pkg, null, 2));
console.log("[patch-rpc-websockets] Patched exports field with deep import paths");

/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// In development the dashboard runs on Vite (http://localhost:5173) and forwards API
// calls to the API container. The Host header is kept ("localhost"), which the API's
// host allowlist accepts. In production the API serves the built files itself.
const apiTarget = process.env.API_PROXY_TARGET ?? "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    strictPort: true,
    proxy: { "/api": { target: apiTarget, changeOrigin: false } },
    // Windows bind mounts do not deliver file-change events to Linux containers.
    watch: { usePolling: process.env.VITE_POLLING === "true" },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    // Everything as files: the CSP forbids inline scripts and styles.
    assetsInlineLimit: 0,
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["src/test/setup.ts"],
  },
});

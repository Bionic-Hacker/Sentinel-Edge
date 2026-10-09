/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";

// Same-origin architecture (ADR-0002): the SPA always calls relative `/api/*` paths.
// Locally, Vite proxies them to the API container; in AWS, CloudFront routes them (Phase 5).
const apiTarget = process.env.SENTINEL_API_PROXY_TARGET ?? "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: "127.0.0.1",
    proxy: { "/api": { target: apiTarget, changeOrigin: false } },
  },
  build: {
    sourcemap: false, // do not ship source maps to end users
    target: "es2022",
    rolldownOptions: {
      output: {
        // React and the router change rarely: a separate chunk stays cached across releases and
        // keeps the application chunk under the 500 kB warning.
        advancedChunks: {
          groups: [{ name: "react", test: /[\\/]node_modules[\\/](react|react-dom|react-router|react-router-dom|scheduler)[\\/]/ }],
        },
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
  },
});

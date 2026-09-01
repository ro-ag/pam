import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig(({ mode }) => ({
  // The tailwind plugin is build/dev-only: under vitest (mode "test") it
  // would compile every stylesheet — swallowing the `?raw` imports the
  // design-contract tests read — and jsdom renders no CSS anyway.
  plugins: mode === "test" ? [react()] : [react(), tailwindcss()],
  clearScreen: false,
  server: {
    // The Tauri dev context loads http://127.0.0.1:1420 (tauri.conf.json
    // devUrl); strictPort makes a port clash fail loudly instead of the
    // window silently pointing at a stale server.
    host: "127.0.0.1",
    port: 1420,
    strictPort: true,
  },
  build: {
    target: ["es2021", "chrome105", "safari13"],
    outDir: "dist",
    emptyOutDir: true,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./vitest.setup.ts"],
    restoreMocks: true,
    // Without this, vitest stubs EVERY css module — including the `?raw`
    // imports the design-contract tests parse — to an empty string.
    css: true,
    coverage: {
      // Report-only visibility (`npm run test:coverage`): no thresholds
      // enforced yet — the views are still churning, and a gate pinned
      // now would freeze layout experiments instead of protecting
      // behavior. Thresholds land once the screens stabilize.
      provider: "v8",
      include: ["src/**/*.{ts,tsx}"],
    },
  },
}));

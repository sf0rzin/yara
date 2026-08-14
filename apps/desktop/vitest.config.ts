import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

/**
 * The frontend test run.
 *
 * Separate from `vite.config.ts` because that one exists to serve Tauri: it
 * pins port 1420 and fails if the port is taken, which would make the test run
 * depend on whether somebody happens to have `tauri dev` open.
 *
 * jsdom rather than a real browser. Everything worth testing here is keyboard
 * handling, focus and what the accessibility tree reports — all of which jsdom
 * models — and the parts that need a real webview need a real Tauri build.
 */
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["./src/test/setup.ts"],
    restoreMocks: true,
  },
});

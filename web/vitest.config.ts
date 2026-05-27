import { defineConfig } from "vitest/config";
import path from "node:path";

/**
 * Vitest config for the dashboard's unit tests. jsdom gives us a DOM
 * for React Testing Library; the `@` alias matches `tsconfig.json` so
 * tests import the same way component code does.
 *
 * ``esbuild.jsx="automatic"`` is required so component source files
 * that rely on the React 17+ automatic JSX runtime (no in-scope
 * ``React`` identifier) render under vitest. Without this, esbuild
 * defaults to the classic runtime and Next-style components blow up
 * with ``ReferenceError: React is not defined``.
 */
export default defineConfig({
  esbuild: {
    jsx: "automatic",
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./__tests__/setup.ts"],
    include: ["__tests__/**/*.{test,spec}.{ts,tsx}"],
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "."),
    },
  },
});

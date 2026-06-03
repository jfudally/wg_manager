import { defineConfig } from "vitest/config";
import path from "node:path";

/**
 * Vitest config for the dashboard's unit tests. jsdom gives us a DOM
 * for React Testing Library; the `@` alias matches `tsconfig.json` so
 * tests import the same way component code does.
 *
 * ``oxc.jsx={ runtime: "automatic" }`` is required so component source
 * files that rely on the React 17+ automatic JSX runtime (no in-scope
 * ``React`` identifier) render under vitest. Without this, oxc treats
 * the source as preserve-mode JSX (carried over from ``tsconfig.json``
 * where ``jsx: "preserve"`` is what Next.js needs at build time) and
 * the .tsx imports blow up at parse time with "invalid JS syntax".
 *
 * Vitest 4 switched the default transformer from esbuild to oxc — the
 * pre-v4 config used ``esbuild.jsx="automatic"`` to achieve the same.
 */
export default defineConfig({
  oxc: {
    jsx: {
      runtime: "automatic",
    },
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

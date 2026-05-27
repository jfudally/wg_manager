import { defineConfig } from "vitest/config";
import path from "node:path";

/**
 * Vitest config for the dashboard's unit tests. jsdom gives us a DOM
 * for React Testing Library; the `@` alias matches `tsconfig.json` so
 * tests import the same way component code does.
 */
export default defineConfig({
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

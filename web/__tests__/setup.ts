/**
 * Vitest global setup. Wires up jest-dom matchers (`toBeInTheDocument`
 * etc.) and seeds the `NEXT_PUBLIC_WG_MANAGER_API` env so the API
 * client doesn't fall back to its localhost default during tests.
 */
import "@testing-library/jest-dom";

process.env.NEXT_PUBLIC_WG_MANAGER_API = "http://test.local";

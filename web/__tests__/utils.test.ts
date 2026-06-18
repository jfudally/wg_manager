import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { formatDateTime, relativeFromNow } from "@/lib/utils";

describe("API timestamp parsing (UTC-naive from backend)", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    // Fixed "now" at 2026-06-18T18:00:30Z.
    vi.setSystemTime(new Date("2026-06-18T18:00:30Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("treats a timezone-naive timestamp from the API as UTC, never future", () => {
    // The backend emits aware-UTC instants without an offset designator,
    // e.g. "2026-06-18T18:00:00". 30s before the fixed now.
    expect(relativeFromNow("2026-06-18T18:00:00")).toBe("30s ago");
  });

  it("parses a naive timestamp identically to its explicit-Z form", () => {
    expect(relativeFromNow("2026-06-18T18:00:00")).toBe(
      relativeFromNow("2026-06-18T18:00:00Z"),
    );
    expect(formatDateTime("2026-06-18T18:00:00")).toBe(
      formatDateTime("2026-06-18T18:00:00Z"),
    );
  });

  it("still honors an explicit timezone offset when present", () => {
    // 18:00:00+02:00 == 16:00:30Z is 2h0m30s before now → rolls up to hours.
    expect(relativeFromNow("2026-06-18T18:00:00+02:00")).toBe("2h ago");
  });
});

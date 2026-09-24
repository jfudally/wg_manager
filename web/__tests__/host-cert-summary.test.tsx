/**
 * Unit test for the shared `HostCertSummary` component's date parsing.
 *
 * The API serializes `host_cert_valid_before` from a timezone-naive DB
 * column, e.g. "2026-09-25T18:23:31" — UTC, but with no designator.
 * `new Date()` reads such a string as *local* time, which skewed the
 * "expires in …" hint by the viewer's UTC offset (8h in Los Angeles —
 * a third of the default 24h cert TTL). The component must parse API
 * timestamps as UTC, like `formatDateTime` does.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { HostCertSummary } from "@/components/host-cert-summary";

const ORIGINAL_TZ = process.env.TZ;

/** Naive-UTC ISO string (API wire shape) `hours` from now. */
function naiveUtcIn(hours: number): string {
  return new Date(Date.now() + hours * 3_600_000).toISOString().replace(/Z$/, "");
}

beforeEach(() => {
  // A zone far from UTC so local-vs-UTC parsing can't coincide.
  process.env.TZ = "America/Los_Angeles";
});

afterEach(() => {
  process.env.TZ = ORIGINAL_TZ;
  cleanup();
});

describe("HostCertSummary", () => {
  it("reads naive API timestamps as UTC", () => {
    render(
      <HostCertSummary
        node={{ host_cert_serial: 1, host_cert_valid_before: naiveUtcIn(5.5) }}
      />,
    );
    expect(screen.getByText(/expires in 5h/)).toBeInTheDocument();
  });

  it("still honours an explicit offset", () => {
    render(
      <HostCertSummary
        node={{
          host_cert_serial: 1,
          host_cert_valid_before: new Date(Date.now() + 5.5 * 3_600_000).toISOString(),
        }}
      />,
    );
    expect(screen.getByText(/expires in 5h/)).toBeInTheDocument();
  });

  it("reports a naive timestamp in the past as expired", () => {
    render(
      <HostCertSummary
        node={{ host_cert_serial: 1, host_cert_valid_before: naiveUtcIn(-2) }}
      />,
    );
    expect(screen.getByText("expired")).toBeInTheDocument();
  });
});

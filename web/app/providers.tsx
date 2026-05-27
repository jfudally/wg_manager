"use client";

import {
  QueryClient,
  QueryClientProvider,
  type QueryClientConfig,
} from "@tanstack/react-query";
import { useState, type ReactNode } from "react";

/**
 * Tuned for a control-plane dashboard: snappy refetches, no aggressive
 * background polling by default (individual queries opt in via
 * `refetchInterval`), and errors surface to the UI rather than retrying
 * silently.
 */
const queryClientConfig: QueryClientConfig = {
  defaultOptions: {
    queries: {
      staleTime: 5_000,
      refetchOnWindowFocus: false,
      retry: 1,
    },
    mutations: {
      retry: 0,
    },
  },
};

/**
 * Wraps the app in a React Query client. Lives in a separate module
 * because providers must be client components but `app/layout.tsx`
 * should stay a server component for streaming + metadata support.
 */
export function Providers({ children }: { children: ReactNode }) {
  // One client per top-level render — never share between requests on
  // the server to avoid leaking cache between users.
  const [client] = useState(() => new QueryClient(queryClientConfig));
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Alert } from "@/components/ui/alert";

/**
 * Overview page. Aggregates one-line stats per resource and gives the
 * operator a single launching pad. Each card links to its detail page
 * for the full table + actions.
 */
export default function OverviewPage() {
  const sshKeys = useQuery({ queryKey: ["ssh-keys"], queryFn: api.listSshKeys });
  const servers = useQuery({ queryKey: ["servers"], queryFn: api.listServers });
  const clients = useQuery({ queryKey: ["clients"], queryFn: api.listClients });
  const discovered = useQuery({
    queryKey: ["discovered-peers", "all"],
    queryFn: api.listAllDiscoveredPeers,
  });

  const stats = [
    {
      label: "SSH Keys",
      value: sshKeys.data?.length ?? "—",
      href: "/ssh-keys",
      description: "Credentials available for provisioning.",
    },
    {
      label: "Servers",
      value: servers.data?.length ?? "—",
      href: "/servers",
      description: `${servers.data?.filter((s) => s.status === "ready").length ?? 0} ready`,
    },
    {
      label: "Clients",
      value: clients.data?.length ?? "—",
      href: "/clients",
      description: `${clients.data?.filter((c) => c.status === "ready").length ?? 0} ready`,
    },
    {
      label: "Discovered Peers",
      value: discovered.data?.length ?? "—",
      href: "/discovered-peers",
      description: `${discovered.data?.filter((p) => p.is_managed).length ?? 0} managed`,
    },
  ];

  const errored = [sshKeys, servers, clients, discovered].find(
    (q) => q.isError,
  );

  return (
    <div className="flex flex-col gap-8">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Overview</h1>
        <p className="text-sm text-muted-foreground">
          Status across every resource the control plane is tracking.
        </p>
      </header>

      {errored ? (
        <Alert variant="error" title="API unreachable">
          Could not reach the wg-manager API. Confirm the FastAPI server is
          running and that <code>NEXT_PUBLIC_WG_MANAGER_API</code> is set to
          its base URL.
        </Alert>
      ) : null}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {stats.map((s) => (
          <Link key={s.label} href={s.href} className="block">
            <Card className="h-full transition-shadow hover:shadow-md">
              <CardHeader>
                <CardTitle>{s.label}</CardTitle>
                <CardDescription>{s.description}</CardDescription>
              </CardHeader>
              <CardContent className="text-3xl font-semibold">
                {s.value}
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Quick actions</CardTitle>
          <CardDescription>
            Common workflows. Each goes to the matching detail page where
            you can fill in the form and dispatch the task.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-3">
          <Link href="/ssh-keys"><Button variant="outline">+ SSH key</Button></Link>
          <Link href="/servers"><Button variant="outline">+ Register server</Button></Link>
          <Link href="/clients"><Button variant="outline">+ Register client</Button></Link>
          <Link href="/discovered-peers"><Button variant="outline">Discover peers</Button></Link>
        </CardContent>
      </Card>
    </div>
  );
}

"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { SSHKey, SSHKeyUpdate } from "@/lib/types";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { EmptyState } from "@/components/empty-state";
import { formatDateTime } from "@/lib/utils";

/**
 * SSH roles page. Phase 2c CP4.4 retired every per-row key material
 * from the schema — a row is a name-and-mode label only. The page is
 * the bare CRUD surface: register a name, rename it, look at it,
 * delete it. The task layer mints a fresh user cert from the SSH CA
 * on every connection; the credential binding lives in Vault's SSH
 * role configuration, not on this row.
 *
 * The pre-CP4.4 "Migrate to CA" flow and the encrypted-key body
 * fields are gone with the migration — by the time an operator can
 * register a role on this page, the role is already CA-mode.
 */
export default function SshKeysPage() {
  const qc = useQueryClient();
  const keysQuery = useQuery({ queryKey: ["ssh-keys"], queryFn: api.listSshKeys });
  const [showForm, setShowForm] = useState(false);
  // Key currently open in the inline edit form, or null when no edit
  // is in progress. Stored as the full row so the form pre-populates
  // name without a re-fetch.
  const [editingKey, setEditingKey] = useState<SSHKey | null>(null);

  return (
    <div className="flex flex-col gap-6">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">SSH Roles</h1>
          <p className="text-sm text-muted-foreground">
            Named roles the control plane uses when SSHing into servers
            and clients. Every connection mints a short-lived user
            certificate from the SSH CA — no private key material is
            stored on the row.
          </p>
        </div>
        <Button onClick={() => setShowForm((v) => !v)}>
          {showForm ? "Cancel" : "+ Add SSH role"}
        </Button>
      </header>

      {showForm ? (
        <AddSshKeyForm
          onAdded={() => {
            setShowForm(false);
            qc.invalidateQueries({ queryKey: ["ssh-keys"] });
          }}
        />
      ) : null}

      {editingKey ? (
        <EditSshKeyForm
          sshKey={editingKey}
          onCancel={() => setEditingKey(null)}
          onSaved={() => {
            setEditingKey(null);
            qc.invalidateQueries({ queryKey: ["ssh-keys"] });
          }}
        />
      ) : null}

      {keysQuery.isError ? (
        <Alert variant="error" title="Couldn't load SSH roles">
          {(keysQuery.error as Error).message}
        </Alert>
      ) : null}

      {keysQuery.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : keysQuery.data && keysQuery.data.length === 0 ? (
        <EmptyState
          title="No SSH roles yet"
          description="Register one so the control plane can SSH into your servers and clients."
        />
      ) : keysQuery.data ? (
        <SshKeyTable
          keys={keysQuery.data}
          onEdit={(k) => setEditingKey(k)}
        />
      ) : null}
    </div>
  );
}

function SshKeyTable({
  keys,
  onEdit,
}: {
  keys: SSHKey[];
  onEdit: (sshKey: SSHKey) => void;
}) {
  const qc = useQueryClient();
  const deleteMutation = useMutation({
    mutationFn: (id: number) => api.deleteSshKey(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["ssh-keys"] }),
  });

  return (
    <div className="flex flex-col gap-2">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[80px]">ID</TableHead>
            <TableHead>Name</TableHead>
            <TableHead>Mode</TableHead>
            <TableHead>Created</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {keys.map((k) => (
            <TableRow key={k.id}>
              <TableCell className="font-mono text-xs">{k.id}</TableCell>
              <TableCell className="font-medium">{k.name}</TableCell>
              <TableCell>
                <Badge variant="success">{k.mode}</Badge>
              </TableCell>
              <TableCell className="text-muted-foreground">
                {formatDateTime(k.created_at)}
              </TableCell>
              <TableCell className="flex justify-end gap-2">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => onEdit(k)}
                >
                  Edit
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    if (
                      window.confirm(
                        `Delete SSH role "${k.name}"? This fails if any server or client still references it.`,
                      )
                    ) {
                      deleteMutation.mutate(k.id);
                    }
                  }}
                  disabled={deleteMutation.isPending}
                >
                  Delete
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {deleteMutation.isError ? (
        <Alert variant="error">
          {(deleteMutation.error as ApiError | Error).message}
        </Alert>
      ) : null}
    </div>
  );
}

function AddSshKeyForm({ onAdded }: { onAdded: () => void }) {
  const [name, setName] = useState("");

  const mutation = useMutation({
    mutationFn: () => api.createSshKey({ name: name.trim() }),
    onSuccess: () => {
      setName("");
      onAdded();
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Add an SSH role</CardTitle>
        <CardDescription>
          Pick a memorable name — the same one you&apos;ll reference
          when registering servers and clients. The role binds to the
          SSH CA configured in Vault; no private key material is
          stored on the row.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="flex flex-col gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            mutation.mutate();
          }}
        >
          <div className="flex flex-col gap-1 max-w-md">
            <Label htmlFor="key-name">Name</Label>
            <Input
              id="key-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="lab-2026"
              required
            />
          </div>
          {mutation.isError ? (
            <Alert variant="error">
              {(mutation.error as ApiError | Error).message}
            </Alert>
          ) : null}
          <CardFooter className="px-0 pb-0">
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? "Saving…" : "Save SSH role"}
            </Button>
          </CardFooter>
        </form>
      </CardContent>
    </Card>
  );
}

/**
 * Inline edit form for an existing SSH role. Phase 2c CP4.4 reduced
 * the editable surface to the display name — the row carries no
 * other mutable state.
 */
function EditSshKeyForm({
  sshKey,
  onCancel,
  onSaved,
}: {
  sshKey: SSHKey;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState(sshKey.name);

  function buildPayload(): SSHKeyUpdate {
    const payload: SSHKeyUpdate = {};
    if (name.trim() !== sshKey.name) payload.name = name.trim();
    return payload;
  }

  const mutation = useMutation({
    mutationFn: () => api.updateSshKey(sshKey.id, buildPayload()),
    onSuccess: () => onSaved(),
  });

  const payloadIsEmpty = Object.keys(buildPayload()).length === 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          Edit SSH role #{sshKey.id} — {sshKey.name}
        </CardTitle>
        <CardDescription>
          Rename the role. The name change propagates to every server
          and client that references it; nothing else needs to
          re-provision.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="flex flex-col gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            mutation.mutate();
          }}
        >
          <div className="flex flex-col gap-1 max-w-md">
            <Label htmlFor="edit-key-name">Name</Label>
            <Input
              id="edit-key-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </div>
          {mutation.isError ? (
            <Alert variant="error">
              {(mutation.error as ApiError | Error).message}
            </Alert>
          ) : null}
          <CardFooter className="px-0 pb-0 flex gap-2">
            <Button
              type="submit"
              disabled={mutation.isPending || payloadIsEmpty}
            >
              {mutation.isPending ? "Saving…" : "Save changes"}
            </Button>
            <Button
              type="button"
              variant="ghost"
              onClick={onCancel}
              disabled={mutation.isPending}
            >
              Cancel
            </Button>
          </CardFooter>
        </form>
      </CardContent>
    </Card>
  );
}

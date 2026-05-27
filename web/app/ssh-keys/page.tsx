"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ApiError, b64encode } from "@/lib/api";
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
 * SSH keys page. Lists registered credentials and exposes inline forms
 * to add or remove them. The PEM file is read on the client and
 * base64-encoded before being POSTed — the raw key never appears in any
 * URL or query string.
 */
export default function SshKeysPage() {
  const qc = useQueryClient();
  const keysQuery = useQuery({ queryKey: ["ssh-keys"], queryFn: api.listSshKeys });
  const [showForm, setShowForm] = useState(false);
  // Key currently open in the inline edit form, or null when no edit is
  // in progress. Stored as the full row so the form pre-populates name
  // without a re-fetch. Passphrase and the PEM body are deliberately NOT
  // available here — the API never returns them — so the form starts
  // those fields blank and only sends what the operator actually typed.
  const [editingKey, setEditingKey] = useState<SSHKey | null>(null);

  return (
    <div className="flex flex-col gap-6">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">SSH Keys</h1>
          <p className="text-sm text-muted-foreground">
            Credentials used by Celery workers to provision and discover nodes.
          </p>
        </div>
        <Button onClick={() => setShowForm((v) => !v)}>
          {showForm ? "Cancel" : "+ Add SSH key"}
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
        <Alert variant="error" title="Couldn't load SSH keys">
          {(keysQuery.error as Error).message}
        </Alert>
      ) : null}

      {keysQuery.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : keysQuery.data && keysQuery.data.length === 0 ? (
        <EmptyState
          title="No SSH keys yet"
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
            <TableHead>Status</TableHead>
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
                {k.encrypted ? (
                  <Badge variant="success">encrypted</Badge>
                ) : (
                  <Badge variant="warn">legacy</Badge>
                )}
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
                        `Delete SSH key "${k.name}"? This fails if any server or client still references it.`,
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
  const [passphrase, setPassphrase] = useState("");
  const [pemBody, setPemBody] = useState("");

  const mutation = useMutation({
    mutationFn: () =>
      api.createSshKey({
        name: name.trim(),
        private_key_b64: b64encode(pemBody),
        passphrase: passphrase ? passphrase : null,
      }),
    onSuccess: () => {
      setName("");
      setPassphrase("");
      setPemBody("");
      onAdded();
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Add an SSH key</CardTitle>
        <CardDescription>
          Paste the PEM body or load it from a file. The private key is
          stored in the control-plane DB only — it never leaves the
          server side.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="grid grid-cols-1 gap-4 md:grid-cols-2"
          onSubmit={(e) => {
            e.preventDefault();
            mutation.mutate();
          }}
        >
          <div className="flex flex-col gap-1">
            <Label htmlFor="key-name">Name</Label>
            <Input
              id="key-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="lab-2026"
              required
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="key-passphrase">Passphrase (optional)</Label>
            <Input
              id="key-passphrase"
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              autoComplete="off"
            />
          </div>
          <div className="md:col-span-2 flex flex-col gap-1">
            <Label htmlFor="key-pem">Private key (PEM)</Label>
            <textarea
              id="key-pem"
              className="min-h-[160px] w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-xs"
              required
              placeholder={"-----BEGIN OPENSSH PRIVATE KEY-----\n..."}
              value={pemBody}
              onChange={(e) => setPemBody(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              Or drop a PEM file:{" "}
              <input
                type="file"
                accept=".pem,.key,.priv"
                className="text-xs"
                onChange={async (e) => {
                  const file = e.target.files?.[0];
                  if (!file) return;
                  setPemBody(await file.text());
                }}
              />
            </p>
          </div>
          {mutation.isError ? (
            <div className="md:col-span-2">
              <Alert variant="error">
                {(mutation.error as ApiError | Error).message}
              </Alert>
            </div>
          ) : null}
          <CardFooter className="md:col-span-2 px-0 pb-0">
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? "Saving…" : "Save SSH key"}
            </Button>
          </CardFooter>
        </form>
      </CardContent>
    </Card>
  );
}

/**
 * Inline edit form for an existing SSH key. The name pre-fills from the
 * current row; the passphrase and PEM body fields start blank because the
 * API never returns them, and only fields the operator actually typed are
 * sent in the PATCH (so leaving a sensitive field blank reliably means
 * "don't change it").
 *
 * Replacing the PEM body does not auto-reprovision servers/clients that
 * already reference this key — they pick up the new credential on their
 * next SSH-touching action (provision / reprovision / discover).
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
  const [passphrase, setPassphrase] = useState("");
  const [pemBody, setPemBody] = useState("");

  // Build a partial payload containing only fields the operator actually
  // changed (rename) or typed into (passphrase, PEM body). The API treats
  // both omitted and `null` fields as "leave unchanged", so a blank
  // passphrase / PEM box is the safe default for "don't rotate".
  function buildPayload(): SSHKeyUpdate {
    const payload: SSHKeyUpdate = {};
    if (name.trim() !== sshKey.name) payload.name = name.trim();
    if (passphrase !== "") payload.passphrase = passphrase;
    if (pemBody !== "") payload.private_key_b64 = b64encode(pemBody);
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
          Edit SSH key #{sshKey.id} — {sshKey.name}
        </CardTitle>
        <CardDescription>
          Rename the credential, rotate its passphrase, or swap the PEM
          body. The passphrase and key body never leave the server, so
          they are not pre-filled here — leave them blank to keep the
          current value. Rotating the key body does not auto-reprovision
          existing servers / clients that use it; they pick up the new
          key on their next provision, reprovision, or discover.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="grid grid-cols-1 gap-4 md:grid-cols-2"
          onSubmit={(e) => {
            e.preventDefault();
            mutation.mutate();
          }}
        >
          <div className="flex flex-col gap-1">
            <Label htmlFor="edit-key-name">Name</Label>
            <Input
              id="edit-key-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="edit-key-passphrase">
              New passphrase (leave blank to keep current)
            </Label>
            <Input
              id="edit-key-passphrase"
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              autoComplete="off"
            />
          </div>
          <div className="md:col-span-2 flex flex-col gap-1">
            <Label htmlFor="edit-key-pem">
              Replacement private key (leave blank to keep current)
            </Label>
            <textarea
              id="edit-key-pem"
              className="min-h-[160px] w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-xs"
              placeholder={"-----BEGIN OPENSSH PRIVATE KEY-----\n..."}
              value={pemBody}
              onChange={(e) => setPemBody(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              Or drop a PEM file:{" "}
              <input
                type="file"
                accept=".pem,.key,.priv"
                className="text-xs"
                onChange={async (e) => {
                  const file = e.target.files?.[0];
                  if (!file) return;
                  setPemBody(await file.text());
                }}
              />
            </p>
          </div>
          {mutation.isError ? (
            <div className="md:col-span-2">
              <Alert variant="error">
                {(mutation.error as ApiError | Error).message}
              </Alert>
            </div>
          ) : null}
          <CardFooter className="md:col-span-2 px-0 pb-0 flex gap-2">
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

# ===========================================================================
# One-shot `vault operator migrate` config: file storage → raft storage.
# ===========================================================================
#
# Consumed only by scripts/vault_migrate_raft.sh (`make
# vault-migrate-raft`), which runs it in a one-off container of the
# `vault` compose service while the server is stopped. Both volumes are
# mounted there exactly as the server sees them:
#
#   * /vault/file — wg_manager_vault_data, the pre-raft storage. Read
#     only by the migration; left intact as the rollback copy.
#   * /vault/raft — wg_manager_vault_raft, the new storage. Must be
#     empty; the script refuses otherwise.
#
# The migration copies the encrypted storage entries verbatim, so the
# unseal keys and root token in vault-init.json keep working.
#
# node_id and cluster_addr MUST match docker/vault/vault.hcl: raft
# membership is recorded under this node_id, and the server only
# recognises itself as the voter if it boots with the same one.
# tests/test_vault_migrate_raft.py enforces the match.
# ===========================================================================

storage_source "file" {
  path = "/vault/file"
}

storage_destination "raft" {
  path    = "/vault/raft"
  node_id = "wg-manager-vault"
}

cluster_addr = "http://vault:8201"

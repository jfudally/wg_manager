# ===========================================================================
# Production Vault config consumed by the docker-compose.prod.yml overlay.
# ===========================================================================
#
# Replaces the dev compose's `vault server -dev` (in-memory + auto-
# unsealed + fixed root token) with a real production posture:
#
#   * File storage backend → Vault data persists across container
#     restarts. The dev-mode regression class (CA keypair regenerated
#     on every `docker restart vault`, breaking every host that had
#     `bootstrap-host` install the old CA pubkey) is closed.
#   * TCP listener on 0.0.0.0:8200 → reachable from the api / worker
#     / bootstrap-* containers via the compose-network DNS name
#     `vault:8200`.
#   * `ui = true` → operator can browse to http://<host>:8200/ui
#     for inspection (SSH CA mount state, PKI hierarchy, Transit key
#     versions). Useful for "why did the api fail to talk to Vault?"
#     diagnostics.
#   * `disable_mlock = true` → boot is portable across hosts where
#     IPC_LOCK isn't guaranteed (kernel-hardened containers, rootless
#     docker). The on-disk-swap leak this mitigates only matters if
#     there's swap, which operator-controlled hosts usually don't
#     have anyway.
#
# **Intentionally NOT configured here**:
#
#   * **Listener TLS**. Vault is the PKI source for every other cert
#     in the stack (api server cert, MySQL TLS, operator client
#     cert). The listener can't depend on a Vault-minted cert at
#     boot — that's the chicken-and-egg loop that costs operators
#     hours when they accidentally set TLS_CERT_FILE here. Until a
#     dedicated listener-TLS cycle ships, Vault talks cleartext on
#     the docker network and operators rely on docker-network
#     isolation as the boundary.
#   * **Cloud-KMS auto-unseal** (transit / awskms / gcpckms). Not
#     viable for an offline / no-cloud deploy. The Phase 2e
#     production-Vault cycle's real next step is to add this as an
#     opt-in for operators with cloud creds. For now,
#     `scripts/vault_init_unseal.sh` does shamir-share auto-unseal
#     from a local `vault-init.json` — documented limitation.
# ===========================================================================

# Storage: file backend persists Vault state across container
# restarts. The compose overlay mounts the `wg_manager_vault_data`
# named volume at `/vault/file` — losing that volume means losing
# Vault (recoverable from `vault operator raft snapshot` backups if
# the operator set them up; see docs/runbooks/backup-restore.md).
storage "file" {
  path = "/vault/file"
}

# Listener: cleartext HTTP on the docker-network. mTLS is enforced
# one hop later by every wg-manager consumer (the api / worker
# containers' hvac clients live on the same docker network).
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = "true"
}

# api_addr advertises where Vault thinks it lives. Must point at
# the listener Vault actually owns — using `127.0.0.1` here would
# work for in-container CLI calls but break Vault's internal API
# redirects (rare in single-node, would matter on HA).
api_addr = "http://vault:8200"

# Cluster addr is irrelevant for a single-node deploy but Vault
# logs a warning if it's unset.
cluster_addr = "http://vault:8201"

# UI on. Tiny operational win for operators inspecting state.
ui = true

# Disable mlock — see the header comment.
disable_mlock = true

# Logging: stdout for `docker logs wg_manager_vault`. JSON makes
# `jq` parsing trivial; level=info is a good default that surfaces
# auth attempts + bootstrap operations without drowning the
# operator in routine reads.
log_format = "json"
log_level  = "info"

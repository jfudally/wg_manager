# One wg-manager enrollment token, managed as a Terraform resource.
#
#   create  -> POST /enrollment-tokens              (mint; the response
#              holds the only copy of the token)
#   read    -> GET  /enrollment-tokens/{id}         (never the token)
#   destroy -> POST /enrollment-tokens/{id}/revoke  (so `terraform
#              destroy`, or replacing the instance, revokes it)
#
# The caller configures the `restapi` provider (URI + mTLS client cert
# of an admin operator); see ../examples/aws-instance.

locals {
  payload = {
    server_id     = var.server_id
    ssh_key_id    = var.ssh_key_id
    ssh_username  = var.ssh_username
    name_prefix   = var.name_prefix
    ttl_seconds   = var.ttl_seconds
    max_uses      = var.max_uses
    allowed_cidrs = var.allowed_cidrs
  }
}

# Tracks the inputs so a change replaces the token (see below).
resource "terraform_data" "inputs" {
  input = local.payload
}

resource "restapi_object" "token" {
  path           = "/enrollment-tokens"
  data           = jsonencode(local.payload)
  destroy_path   = "/enrollment-tokens/{id}/revoke"
  destroy_method = "POST"

  # The server's view changes on its own (use_count, status, and
  # computed fields such as expires_at instead of ttl_seconds). None of
  # that is drift to "fix", so the provider never plans an update from it.
  ignore_all_server_changes = true

  lifecycle {
    # A token can't be edited, only replaced: any input change revokes
    # this one and mints a new one. This is done in Terraform rather
    # than with the provider's force_new, which ignore_all_server_changes
    # suppresses (an input change planned as "no changes").
    replace_triggered_by = [terraform_data.inputs]
  }
}

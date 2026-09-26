# wg-manager-enrollment-token

Terraform module that mints one wg-manager enrollment token per use, for
a new host's userdata (see `scripts/enroll_node.sh` and the operator
guide, "Zero-touch enrollment").

| Terraform action | API call |
| --- | --- |
| create | `POST /v1/enrollment-tokens` (the response is the only copy of the token) |
| refresh | `GET /v1/enrollment-tokens/{id}` (never returns the token) |
| destroy | `POST /v1/enrollment-tokens/{id}/revoke` |
| any input change | revoke the old token and mint a new one |

## Usage

The caller configures the [`Mastercard/restapi`](https://registry.terraform.io/providers/Mastercard/restapi)
provider with the operator API URL and an **admin** operator's client
certificate. `create_returns_object = true` is required:

```hcl
provider "restapi" {
  uri                   = "https://wg.example.com/v1"
  cert_file             = "ops.crt"
  key_file              = "ops.key"
  root_ca_file          = "ca-bundle.crt"
  create_returns_object = true
  id_attribute          = "id"
}

module "enroll_token" {
  source = "path/to/deploy/terraform/wg-manager-enrollment-token"

  server_id     = 1
  ssh_key_id    = 1
  ssh_username  = "wgmgr"
  ttl_seconds   = 1800
  allowed_cidrs = ["203.0.113.7/32"] # your NAT gateway's public IP
}

# module.enroll_token.token -> WGM_ENROLL_TOKEN in the instance's userdata
```

See [`../examples/aws-instance`](../examples/aws-instance) for a complete
EC2 example.

## Inputs

| Name | Default | Description |
| --- | --- | --- |
| `server_id` | (required) | Hub the host joins. Must be `ready`. |
| `ssh_key_id` | (required) | SSH role the worker manages the host with. |
| `ssh_username` | (required) | Account the worker logs in as. |
| `name_prefix` | `"node"` | Client is named `<prefix>-<hostname>`. |
| `ttl_seconds` | `3600` | 60 to 604800. The instance must boot and enroll within this after `apply`. |
| `max_uses` | `1` | Keep at 1 for a per-instance token. |
| `allowed_cidrs` | `null` | 1 to 16 networks the token works from; `null` = anywhere. |

## Outputs

| Name | Description |
| --- | --- |
| `token` | The token (sensitive). |
| `id` | Token id (`wg-manager enroll-tokens list`). |
| `expires_at` | When it stops working (UTC). |

## Things to know

- **The token is in Terraform state**, as is the rendered userdata. Treat
  state as secret. The token is single-use, short-lived and optionally
  source-bound, which limits the damage if state leaks.
- **Pair it with `ignore_changes = [user_data]`** on the instance.
  Userdata only matters on first boot. Once the sweeper deletes a
  long-dead token (7 days after expiry by default), the next plan mints
  a fresh one. That's harmless: it's never used, expires on its own, and
  is revoked on destroy. It must not replace the enrolled host, though.
- **restapi is pinned to 2.x.** 3.0.0 mishandles the 404 for a swept
  token and breaks both plan and destroy.
- **Autoscaling groups:** a launch template's userdata is fixed, so this
  gives every instance the *same* token. Use `max_uses` equal to the
  group's maximum and a TTL that covers scale-outs (7 days at most), or
  mint per launch outside Terraform. Instance-identity attestation
  (ROADMAP Phase 3f polish) is the long-term fix.

`make terraform-check` runs `terraform fmt -check` and `validate` here.

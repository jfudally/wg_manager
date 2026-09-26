terraform {
  required_version = ">= 1.5"

  required_providers {
    # Community provider for generic REST objects. It speaks mTLS
    # (cert_file / key_file / root_ca_file on the provider block), lets
    # destroy call the revoke endpoint, and keeps the create response,
    # which is the only place the token plaintext ever appears.
    #
    # Pinned to 2.x: 3.0.0 mishandles a 404 on read. Once the sweeper
    # deletes a long-dead token, 3.0.0 sets `data` to "" and fails its
    # own JSON validation, which breaks plan and destroy. 2.x treats the
    # 404 as "gone" (plan: create a fresh token; destroy: succeeds).
    # Tested end to end against the API with both versions.
    restapi = {
      source  = "Mastercard/restapi"
      version = "~> 2.0"
    }
  }
}

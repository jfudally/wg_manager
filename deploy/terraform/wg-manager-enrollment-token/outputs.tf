output "token" {
  description = "The enrollment token, for the host's userdata (WGM_ENROLL_TOKEN). Only available from the create response; stored in Terraform state."
  value       = jsondecode(restapi_object.token.create_response).token
  sensitive   = true
}

output "id" {
  description = "Token id, as shown by `wg-manager enroll-tokens list`."
  value       = restapi_object.token.id
}

output "expires_at" {
  description = "When the token stops working (UTC). The instance must boot and enroll before then."
  value       = jsondecode(restapi_object.token.create_response).expires_at
}

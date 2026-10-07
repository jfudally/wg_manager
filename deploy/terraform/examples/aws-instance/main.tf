# Example: one EC2 instance that enrolls itself into wg-manager on first
# boot, with its own single-use token.
#
#   terraform init && terraform apply
#
# Terraform mints the token (as an admin operator, over mTLS), puts it in
# the instance's userdata, and revokes it on destroy. Everything below
# the provider blocks is illustrative: swap in your own AMI, subnet and
# sizing.

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    restapi = {
      source  = "Mastercard/restapi"
      version = "~> 2.0" # not 3.x: see ../../wg-manager-enrollment-token/versions.tf
    }
  }
}

variable "wg_manager_api_url" {
  description = "Operator API, including /v1, e.g. https://wg.example.com/v1."
  type        = string
}

variable "wg_manager_enroll_url" {
  description = "Enrollment listener the host calls, e.g. https://wg.example.com:8443."
  type        = string
}

variable "operator_cert_file" {
  description = "PEM client cert of an admin operator (wg-manager certs issue ...)."
  type        = string
}

variable "operator_key_file" {
  description = "Private key for operator_cert_file."
  type        = string
}

variable "ca_bundle_file" {
  description = "tls/ca-bundle.crt: verifies the API, and the host uses it to verify the enroll listener."
  type        = string
}

variable "hub_server_id" {
  type = number
}

variable "ssh_key_id" {
  type = number
}

variable "ami_id" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "nat_gateway_ip" {
  description = "Public address the subnet's traffic leaves from; the token only works from there."
  type        = string
}

provider "restapi" {
  uri          = var.wg_manager_api_url
  cert_file    = var.operator_cert_file
  key_file     = var.operator_key_file
  root_ca_file = var.ca_bundle_file
  # Required by the module: POST /enrollment-tokens answers with the new
  # token (id + plaintext), and restapi must take the id from that
  # response rather than expect it in the request.
  create_returns_object = true
  id_attribute          = "id"
}

provider "aws" {}

module "enroll_token" {
  source = "../../wg-manager-enrollment-token"

  server_id     = var.hub_server_id
  ssh_key_id    = var.ssh_key_id
  ssh_username  = "wgmgr"
  name_prefix   = "web"
  ttl_seconds   = 1800
  max_uses      = 1
  allowed_cidrs = ["${var.nat_gateway_ip}/32"]
}

resource "aws_instance" "web" {
  ami           = var.ami_id
  instance_type = "t3.small"
  subnet_id     = var.subnet_id

  user_data = templatefile("${path.module}/userdata.sh.tftpl", {
    enroll_url = var.wg_manager_enroll_url
    token      = module.enroll_token.token
    ca_bundle  = file(var.ca_bundle_file)
  })

  # Userdata only matters on first boot. Without this, re-minting the
  # token (an input change, or the sweeper deleting the long-dead row so
  # Terraform plans a new one) would replace a healthy, enrolled host.
  lifecycle {
    ignore_changes = [user_data]
  }
}

output "enroll_token_id" {
  value = module.enroll_token.id
}

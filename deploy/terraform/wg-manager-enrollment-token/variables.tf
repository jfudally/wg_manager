variable "server_id" {
  description = "Hub the enrolled host joins. Must be `ready`."
  type        = number
}

variable "ssh_key_id" {
  description = "SSH role the worker manages the host with. Must be in the hub's tenant."
  type        = number
}

variable "ssh_username" {
  description = "Account the worker logs in as on the host (created with passwordless sudo by enroll_node.sh)."
  type        = string
}

variable "name_prefix" {
  description = "The client is named <name_prefix>-<hostname>."
  type        = string
  default     = "node"
}

variable "ttl_seconds" {
  description = "Token lifetime, 60 to 604800. Keep it close to how long a boot takes after `apply`."
  type        = number
  default     = 3600

  validation {
    condition     = var.ttl_seconds >= 60 && var.ttl_seconds <= 604800
    error_message = "ttl_seconds must be between 60 and 604800 (7 days)."
  }
}

variable "max_uses" {
  description = "Hosts the token may enroll. Leave at 1 for a per-instance token."
  type        = number
  default     = 1

  validation {
    condition     = var.max_uses >= 1 && var.max_uses <= 100
    error_message = "max_uses must be between 1 and 100."
  }
}

variable "allowed_cidrs" {
  description = "Optional networks (1 to 16) the token may be redeemed from, e.g. the subnet's NAT gateway address. null = anywhere."
  type        = list(string)
  default     = null

  validation {
    condition     = var.allowed_cidrs == null ? true : (length(var.allowed_cidrs) >= 1 && length(var.allowed_cidrs) <= 16)
    error_message = "allowed_cidrs must be null or list 1 to 16 networks."
  }
}

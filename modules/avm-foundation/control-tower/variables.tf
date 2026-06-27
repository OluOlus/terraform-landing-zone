# Variables for AWS Control Tower Landing Zone Module

variable "enabled" {
  description = "Enable AWS Control Tower landing zone management."
  type        = bool
  default     = false
}

variable "landing_zone_version" {
  description = "AWS Control Tower landing zone version to deploy. Confirm the currently supported version before enabling."
  type        = string
  default     = null

  validation {
    condition     = !var.enabled || (var.landing_zone_version != null && length(var.landing_zone_version) > 0)
    error_message = "landing_zone_version must be set when Control Tower is enabled."
  }
}

variable "governed_regions" {
  description = "AWS regions governed by Control Tower."
  type        = list(string)
  default     = ["eu-west-2", "eu-west-1"]

  validation {
    condition     = alltrue([for region in var.governed_regions : contains(["eu-west-2", "eu-west-1"], region)])
    error_message = "Governed regions must stay within the approved UK/Ireland region set."
  }
}

variable "organization_structure" {
  description = "Control Tower organization structure block for the landing zone manifest."
  type = object({
    security = object({
      name = string
    })
    sandbox = object({
      name = string
    })
  })
  default = {
    security = {
      name = "Security"
    }
    sandbox = {
      name = "Sandbox"
    }
  }
}

variable "log_archive_account_id" {
  description = "Account ID for the Control Tower Log Archive account."
  type        = string
  default     = null

  validation {
    condition     = !var.enabled || can(regex("^[0-9]{12}$", var.log_archive_account_id))
    error_message = "log_archive_account_id must be a 12-digit AWS account ID when Control Tower is enabled."
  }
}

variable "audit_account_id" {
  description = "Account ID for the Control Tower Audit/Security account."
  type        = string
  default     = null

  validation {
    condition     = !var.enabled || can(regex("^[0-9]{12}$", var.audit_account_id))
    error_message = "audit_account_id must be a 12-digit AWS account ID when Control Tower is enabled."
  }
}

variable "enable_centralized_logging" {
  description = "Enable Control Tower centralized logging."
  type        = bool
  default     = true
}

variable "logging_bucket_retention_days" {
  description = "Retention in days for the Control Tower logging bucket."
  type        = number
  default     = 2555
}

variable "access_logging_bucket_retention_days" {
  description = "Retention in days for the Control Tower access logging bucket."
  type        = number
  default     = 2555
}

variable "enable_iam_identity_center" {
  description = "Enable IAM Identity Center through the Control Tower landing zone manifest."
  type        = bool
  default     = true
}

variable "remediation_types" {
  description = "Control Tower landing zone remediation actions to apply, such as INHERITANCE_DRIFT."
  type        = list(string)
  default     = []
}

variable "enabled_controls" {
  description = "Map of Control Tower controls to enable after landing zone creation."
  type = map(object({
    control_identifier = string
    target_identifier  = string
    parameters         = optional(map(string), {})
  }))
  default = {}
}

variable "common_tags" {
  description = "Common tags to apply to Control Tower resources."
  type        = map(string)
  default     = {}
}

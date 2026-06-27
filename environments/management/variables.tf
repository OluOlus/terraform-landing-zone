# Management Environment Variables

variable "organization_name" {
  description = "Name of the AWS Organization"
  type        = string
  default     = "UK Secure Landing Zone"
}

variable "allowed_account_ids" {
  description = "AWS account IDs that Terraform is allowed to manage for this environment. Leave empty only for initial bootstrap."
  type        = list(string)
  default     = []
}

variable "owner_email" {
  description = "Email address of the infrastructure owner"
  type        = string
}

variable "ops_team_email" {
  description = "Email address for operations team notifications"
  type        = string
}

variable "monthly_budget_limit" {
  description = "Monthly budget limit in USD"
  type        = string
  default     = "10000"
}

variable "enable_control_tower" {
  description = "Enable AWS Control Tower landing zone management. When true, the custom organization module is disabled so Control Tower owns baseline OUs and guardrails."
  type        = bool
  default     = false
}

variable "control_tower_landing_zone_version" {
  description = "AWS Control Tower landing zone version to deploy. Confirm the currently supported version before enabling."
  type        = string
  default     = null
}

variable "control_tower_governed_regions" {
  description = "Regions governed by AWS Control Tower."
  type        = list(string)
  default     = ["eu-west-2", "eu-west-1"]
}

variable "control_tower_organization_structure" {
  description = "Control Tower organization structure for the landing zone manifest."
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

variable "control_tower_log_archive_account_id" {
  description = "Account ID for the Control Tower Log Archive account."
  type        = string
  default     = null
}

variable "control_tower_audit_account_id" {
  description = "Account ID for the Control Tower Audit/Security account."
  type        = string
  default     = null
}

variable "control_tower_enable_centralized_logging" {
  description = "Enable centralized logging through the Control Tower landing zone manifest."
  type        = bool
  default     = true
}

variable "control_tower_logging_bucket_retention_days" {
  description = "Retention in days for the Control Tower logging bucket."
  type        = number
  default     = 2555
}

variable "control_tower_access_logging_bucket_retention_days" {
  description = "Retention in days for the Control Tower access logging bucket."
  type        = number
  default     = 2555
}

variable "control_tower_enable_iam_identity_center" {
  description = "Enable IAM Identity Center through the Control Tower landing zone manifest."
  type        = bool
  default     = true
}

variable "control_tower_remediation_types" {
  description = "Control Tower landing zone remediation actions to apply, such as INHERITANCE_DRIFT."
  type        = list(string)
  default     = []
}

variable "control_tower_enabled_controls" {
  description = "Map of Control Tower controls to enable after landing zone creation."
  type = map(object({
    control_identifier = string
    target_identifier  = string
    parameters         = optional(map(string), {})
  }))
  default = {}
}

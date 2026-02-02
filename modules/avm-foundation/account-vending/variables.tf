# Variables for Account Vending Module

variable "workload_accounts" {
  description = "Map of workload accounts to create with their configurations"
  type = map(object({
    name                      = string
    email                     = string
    organizational_unit_id    = string
    account_type              = string
    data_classification       = string
    environment               = string
    cost_center               = string
    owner                     = string
    project                   = string
    backup_schedule           = optional(string, "daily")
    maintenance_window        = optional(string, "sun:03:00-sun:04:00")
    monthly_budget_limit      = optional(number, 1000)
    budget_notification_email = string
    external_id               = string
    tags                      = optional(map(string), {})
  }))
  default = {}

  validation {
    condition = alltrue([
      for account in values(var.workload_accounts) :
      can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", account.email))
    ])
    error_message = "All account emails must be valid email addresses."
  }

  validation {
    condition = alltrue([
      for account in values(var.workload_accounts) :
      contains(["production", "non-production", "sandbox", "security", "logging", "networking"], account.environment)
    ])
    error_message = "Environment must be one of: production, non-production, sandbox, security, logging, networking."
  }

  validation {
    condition = alltrue([
      for account in values(var.workload_accounts) :
      contains(["public", "internal", "confidential", "restricted"], account.data_classification)
    ])
    error_message = "Data classification must be one of: public, internal, confidential, restricted."
  }

  validation {
    condition = alltrue([
      for account in values(var.workload_accounts) :
      contains(["workload", "security", "logging", "networking", "shared-services"], account.account_type)
    ])
    error_message = "Account type must be one of: workload, security, logging, networking, shared-services."
  }
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Project             = "UK-AWS-Secure-Landing-Zone"
    ManagedBy           = "Terraform"
    ComplianceFramework = "Security Standards-Cloud-Security-Principles"
    DataResidency       = "UK"
  }
}

variable "account_access_role_name" {
  description = "Name of the IAM role to create in new accounts for cross-account access"
  type        = string
  default     = "OrganizationAccountAccessRole"
}

variable "iam_user_access_to_billing" {
  description = "Whether IAM users in the account can access billing information"
  type        = string
  default     = "ALLOW"
  validation {
    condition     = contains(["ALLOW", "DENY"], var.iam_user_access_to_billing)
    error_message = "IAM user access to billing must be either ALLOW or DENY."
  }
}

variable "close_on_deletion" {
  description = "Whether to close the account when it is deleted from Terraform"
  type        = bool
  default     = false
}

variable "security_account_id" {
  description = "AWS Account ID of the Security Tooling Account"
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.security_account_id))
    error_message = "Security account ID must be a valid 12-digit AWS account ID."
  }
}

variable "logging_account_id" {
  description = "AWS Account ID of the Log Archive Account"
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.logging_account_id))
    error_message = "Logging account ID must be a valid 12-digit AWS account ID."
  }
}

variable "enable_account_kms_keys" {
  description = "Whether to create account-specific KMS keys for encryption"
  type        = bool
  default     = true
}

variable "kms_key_deletion_window" {
  description = "Number of days to wait before deleting KMS keys"
  type        = number
  default     = 7
  validation {
    condition     = var.kms_key_deletion_window >= 7 && var.kms_key_deletion_window <= 30
    error_message = "KMS key deletion window must be between 7 and 30 days."
  }
}

variable "create_baseline_s3_buckets" {
  description = "Whether to create baseline S3 buckets for account configuration"
  type        = bool
  default     = true
}

variable "force_destroy_buckets" {
  description = "Force destroy S3 buckets even if they contain objects (use with caution)"
  type        = bool
  default     = false
}

variable "s3_lifecycle_expiration_days" {
  description = "Number of days after which S3 objects expire"
  type        = number
  default     = 2555 # 7 years for compliance
  validation {
    condition     = var.s3_lifecycle_expiration_days >= 365
    error_message = "S3 lifecycle expiration must be at least 365 days for compliance."
  }
}

variable "create_account_budgets" {
  description = "Whether to create AWS Budgets for cost management"
  type        = bool
  default     = true
}

variable "deploy_baseline_stackset" {
  description = "Whether to deploy baseline configuration using CloudFormation StackSets"
  type        = bool
  default     = true
}

variable "organizational_unit_deployments" {
  description = "Map of organizational units where baseline StackSet should be deployed"
  type = map(object({
    ou_id  = string
    region = string
  }))
  default = {}
}

variable "aws_regions" {
  description = "List of allowed AWS regions for UK data residency"
  type        = list(string)
  default     = ["us-west-2", "us-east-1"]
  validation {
    condition = alltrue([
      for region in var.aws_regions : contains(["us-west-2", "us-east-1"], region)
    ])
    error_message = "Only specified regions (us-west-2, us-east-1) are allowed for data residency compliance."
  }
}

variable "account_provisioning_timeout" {
  description = "Timeout for account provisioning in minutes"
  type        = number
  default     = 30
  validation {
    condition     = var.account_provisioning_timeout >= 10 && var.account_provisioning_timeout <= 60
    error_message = "Account provisioning timeout must be between 10 and 60 minutes."
  }
}

variable "enable_cross_account_roles" {
  description = "Whether to create cross-account access roles"
  type        = bool
  default     = true
}

variable "cross_account_role_policies" {
  description = "List of additional IAM policy ARNs to attach to cross-account roles"
  type        = list(string)
  default     = []
}

variable "enable_config_baseline" {
  description = "Whether to enable AWS Config baseline configuration"
  type        = bool
  default     = true
}

variable "enable_cloudtrail_baseline" {
  description = "Whether to enable CloudTrail baseline configuration"
  type        = bool
  default     = true
}

variable "enable_guardduty_baseline" {
  description = "Whether to enable GuardDuty baseline configuration"
  type        = bool
  default     = true
}

variable "enable_security_hub_baseline" {
  description = "Whether to enable Security Hub baseline configuration"
  type        = bool
  default     = true
}

variable "notification_email" {
  description = "Email address for account provisioning notifications"
  type        = string
  default     = ""
  validation {
    condition     = var.notification_email == "" || can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.notification_email))
    error_message = "Notification email must be a valid email address or empty string."
  }
}
variable "aws_region" {
  description = "AWS region for Security Automation deployment"
  type        = string
  default     = "us-east-1"

  validation {
    condition     = contains(["us-west-2", "us-east-1"], var.aws_region)
    error_message = "AWS region must be a specified region (us-west-2 or us-east-1) for UK data residency compliance."
  }
}

variable "remediation_bucket_prefix" {
  description = "Prefix for the S3 bucket storing remediation artifacts"
  type        = string
  default     = "uk-security-automation-artifacts"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]*[a-z0-9]$", var.remediation_bucket_prefix))
    error_message = "Bucket prefix must be a valid S3 bucket name prefix (lowercase letters, numbers, and hyphens only)."
  }
}

variable "remediation_log_retention_days" {
  description = "Number of days to retain remediation logs in S3"
  type        = number
  default     = 2555 # 7 years for compliance

  validation {
    condition     = var.remediation_log_retention_days >= 365 && var.remediation_log_retention_days <= 2555
    error_message = "Log retention must be between 1 year (365 days) and 7 years (2555 days) for compliance."
  }
}

variable "cloudwatch_log_retention_days" {
  description = "Number of days to retain CloudWatch logs"
  type        = number
  default     = 365

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.cloudwatch_log_retention_days)
    error_message = "CloudWatch log retention must be a valid retention period."
  }
}

variable "remediation_severity_levels" {
  description = "Security Hub severity levels that trigger automated remediation"
  type        = list(string)
  default     = ["HIGH", "CRITICAL"]

  validation {
    condition     = alltrue([for level in var.remediation_severity_levels : contains(["LOW", "MEDIUM", "HIGH", "CRITICAL"], level)])
    error_message = "Severity levels must be one of: LOW, MEDIUM, HIGH, CRITICAL."
  }
}

variable "guardduty_remediation_severities" {
  description = "GuardDuty severity levels that trigger automated remediation (0.0-10.0)"
  type        = list(number)
  default     = [7.0, 8.0, 8.5, 9.0, 10.0]

  validation {
    condition     = alltrue([for severity in var.guardduty_remediation_severities : severity >= 0.0 && severity <= 10.0])
    error_message = "GuardDuty severity levels must be between 0.0 and 10.0."
  }
}

variable "enable_s3_public_access_remediation" {
  description = "Enable automated remediation for S3 public access violations"
  type        = bool
  default     = true
}

variable "enable_unencrypted_volumes_remediation" {
  description = "Enable automated remediation for unencrypted EBS volumes"
  type        = bool
  default     = true
}

variable "enable_untagged_resources_remediation" {
  description = "Enable automated remediation for untagged resources"
  type        = bool
  default     = true
}

variable "lambda_timeout" {
  description = "Timeout for Lambda functions in seconds"
  type        = number
  default     = 300

  validation {
    condition     = var.lambda_timeout >= 30 && var.lambda_timeout <= 900
    error_message = "Lambda timeout must be between 30 and 900 seconds."
  }
}

variable "lambda_memory_size" {
  description = "Memory size for Lambda functions in MB"
  type        = number
  default     = 512

  validation {
    condition     = var.lambda_memory_size >= 128 && var.lambda_memory_size <= 10240
    error_message = "Lambda memory size must be between 128 and 10240 MB."
  }
}

variable "notification_email" {
  description = "Email address for security automation notifications"
  type        = string
  default     = null

  validation {
    condition     = var.notification_email == null || can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.notification_email))
    error_message = "Notification email must be a valid email address."
  }
}

variable "enable_cross_account_remediation" {
  description = "Enable cross-account remediation capabilities"
  type        = bool
  default     = false
}

variable "trusted_remediation_accounts" {
  description = "List of AWS account IDs trusted for cross-account remediation"
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for account in var.trusted_remediation_accounts : can(regex("^[0-9]{12}$", account))])
    error_message = "All trusted account IDs must be valid 12-digit AWS account IDs."
  }
}

variable "remediation_dry_run" {
  description = "Enable dry-run mode for remediation actions (log only, no actual changes)"
  type        = bool
  default     = false
}

variable "enable_manual_approval" {
  description = "Require manual approval for high-impact remediation actions"
  type        = bool
  default     = true
}

variable "approval_timeout_minutes" {
  description = "Timeout for manual approval in minutes"
  type        = number
  default     = 60

  validation {
    condition     = var.approval_timeout_minutes >= 5 && var.approval_timeout_minutes <= 1440
    error_message = "Approval timeout must be between 5 minutes and 24 hours (1440 minutes)."
  }
}

variable "enable_compliance_reporting" {
  description = "Enable automated compliance reporting for remediation actions"
  type        = bool
  default     = true
}

variable "compliance_report_frequency" {
  description = "Frequency for compliance reports (daily, weekly, monthly)"
  type        = string
  default     = "weekly"

  validation {
    condition     = contains(["daily", "weekly", "monthly"], var.compliance_report_frequency)
    error_message = "Compliance report frequency must be one of: daily, weekly, monthly."
  }
}

variable "enable_cost_optimization" {
  description = "Enable cost optimization features for remediation resources"
  type        = bool
  default     = true
}

variable "common_tags" {
  description = "Common tags to apply to all Security Automation resources"
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      contains(keys(var.common_tags), "DataClassification"),
      contains(keys(var.common_tags), "Environment"),
      contains(keys(var.common_tags), "CostCenter")
    ])
    error_message = "Common tags must include mandatory UK tags: DataClassification, Environment, and CostCenter."
  }
}

variable "uk_data_classification_tags" {
  description = "region-specific data classification tags for mandatory tagging remediation"
  type        = list(string)
  default     = ["public", "internal", "confidential", "restricted"]

  validation {
    condition     = alltrue([for tag in var.uk_data_classification_tags : contains(["public", "internal", "confidential", "restricted"], tag)])
    error_message = "UK data classification tags must be one of: public, internal, confidential, restricted."
  }
}

variable "mandatory_uk_tags" {
  description = "List of mandatory UK tags that must be present on all resources"
  type        = list(string)
  default     = ["DataClassification", "Environment", "CostCenter", "Owner", "Project"]
}

variable "ncsc_compliance_mode" {
  description = "Enable Security Standards Cloud Security Principles compliance mode"
  type        = bool
  default     = true
}

variable "uk_gdpr_compliance_mode" {
  description = "Enable GDPR compliance mode"
  type        = bool
  default     = true
}

variable "cyber_essentials_compliance_mode" {
  description = "Enable Security Essentials compliance mode"
  type        = bool
  default     = true
}
# Variables for GuardDuty Detectors Module

variable "enable_detector" {
  description = "Enable GuardDuty detector"
  type        = bool
  default     = true
}

variable "finding_publishing_frequency" {
  description = "Frequency of notifications sent about subsequent finding occurrences"
  type        = string
  default     = "FIFTEEN_MINUTES"
  validation {
    condition = contains([
      "FIFTEEN_MINUTES",
      "ONE_HOUR",
      "SIX_HOURS"
    ], var.finding_publishing_frequency)
    error_message = "Finding publishing frequency must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}

variable "enable_s3_logs" {
  description = "Enable S3 data source for GuardDuty"
  type        = bool
  default     = true
}

variable "enable_kubernetes_audit_logs" {
  description = "Enable Kubernetes audit logs data source"
  type        = bool
  default     = true
}

variable "enable_malware_protection" {
  description = "Enable malware protection for EC2 instances"
  type        = bool
  default     = true
}

variable "is_organization_admin" {
  description = "Whether this account is the GuardDuty organization admin"
  type        = bool
  default     = false
}

variable "organization_admin_account_id" {
  description = "Account ID for GuardDuty organization admin"
  type        = string
  default     = null
}

variable "auto_enable_organization" {
  description = "Auto-enable GuardDuty for new organization accounts"
  type        = bool
  default     = true
}

variable "auto_enable_organization_members" {
  description = "Auto-enable GuardDuty for organization member accounts"
  type        = string
  default     = "ALL"
  validation {
    condition = contains([
      "ALL",
      "NEW",
      "NONE"
    ], var.auto_enable_organization_members)
    error_message = "Auto enable organization members must be ALL, NEW, or NONE."
  }
}

variable "auto_enable_s3_logs" {
  description = "Auto-enable S3 logs for organization members"
  type        = bool
  default     = true
}

variable "auto_enable_kubernetes_audit_logs" {
  description = "Auto-enable Kubernetes audit logs for organization members"
  type        = bool
  default     = true
}

variable "auto_enable_malware_protection" {
  description = "Auto-enable malware protection for organization members"
  type        = bool
  default     = true
}

variable "enable_publishing_destination" {
  description = "Enable GuardDuty publishing destination"
  type        = bool
  default     = false
}

variable "findings_destination_arn" {
  description = "ARN of the S3 bucket for GuardDuty findings"
  type        = string
  default     = null
}

variable "findings_kms_key_arn" {
  description = "ARN of the KMS key for encrypting GuardDuty findings"
  type        = string
  default     = null
}

variable "member_accounts" {
  description = "Map of member accounts to invite to GuardDuty"
  type = map(object({
    account_id                 = string
    email                      = string
    invite                     = bool
    disable_email_notification = bool
  }))
  default = {}
}

variable "uk_regions" {
  description = "List of UK AWS regions"
  type        = list(string)
  default     = ["us-west-2", "us-east-1"]
}

variable "environment" {
  description = "Environment name (production, non-production, sandbox)"
  type        = string
  default     = "production"
  validation {
    condition = contains([
      "production",
      "non-production",
      "sandbox"
    ], var.environment)
    error_message = "Environment must be production, non-production, or sandbox."
  }
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}
# Variables for GuardDuty Module

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

variable "is_delegated_admin" {
  description = "Whether this account is the GuardDuty delegated admin"
  type        = bool
  default     = false
}

variable "admin_account_id" {
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

# UK Threat Intelligence Variables
variable "enable_uk_threat_intelligence" {
  description = "Enable UK government threat intelligence feeds"
  type        = bool
  default     = true
}

variable "uk_government_threat_list_location" {
  description = "S3 location of UK government threat intelligence list"
  type        = string
  default     = null
}

variable "uk_government_threat_list_url" {
  description = "URL for UK government threat intelligence updates"
  type        = string
  default     = null
}

variable "enable_ncsc_threat_intelligence" {
  description = "Enable Security Standards threat intelligence feeds"
  type        = bool
  default     = true
}

variable "ncsc_threat_list_location" {
  description = "S3 location of Security Standards threat intelligence list"
  type        = string
  default     = null
}

variable "ncsc_threat_list_url" {
  description = "URL for Security Standards threat intelligence updates"
  type        = string
  default     = null
}

variable "enable_financial_threat_intelligence" {
  description = "Enable UK financial services threat intelligence"
  type        = bool
  default     = false
}

variable "financial_threat_list_location" {
  description = "S3 location of financial services threat intelligence list"
  type        = string
  default     = null
}

variable "enable_healthcare_threat_intelligence" {
  description = "Enable UK healthcare threat intelligence"
  type        = bool
  default     = false
}

variable "healthcare_threat_list_location" {
  description = "S3 location of healthcare threat intelligence list"
  type        = string
  default     = null
}

variable "enable_brexit_threat_intelligence" {
  description = "Enable Brexit-related threat intelligence"
  type        = bool
  default     = false
}

variable "brexit_threat_list_location" {
  description = "S3 location of Brexit-related threat intelligence list"
  type        = string
  default     = null
}

variable "enable_cni_threat_intelligence" {
  description = "Enable UK critical national infrastructure threat intelligence"
  type        = bool
  default     = false
}

variable "cni_threat_list_location" {
  description = "S3 location of CNI threat intelligence list"
  type        = string
  default     = null
}

variable "enable_uk_government_allowlist" {
  description = "Enable UK government IP allowlist"
  type        = bool
  default     = true
}

variable "uk_government_allowlist_location" {
  description = "S3 location of UK government IP allowlist"
  type        = string
  default     = null
}

variable "enable_uk_targeted_threats_blocklist" {
  description = "Enable UK-targeted threats blocklist"
  type        = bool
  default     = true
}

variable "uk_targeted_threats_location" {
  description = "S3 location of UK-targeted threats blocklist"
  type        = string
  default     = null
}

variable "enable_automated_threat_intel_updates" {
  description = "Enable automated threat intelligence updates"
  type        = bool
  default     = false
}

variable "threat_intel_updater_zip_path" {
  description = "Path to threat intelligence updater Lambda zip file"
  type        = string
  default     = null
}

variable "threat_intel_s3_bucket" {
  description = "S3 bucket for threat intelligence storage"
  type        = string
  default     = null
}

variable "threat_intel_s3_bucket_arn" {
  description = "ARN of S3 bucket for threat intelligence storage"
  type        = string
  default     = null
}

variable "threat_intel_kms_key_id" {
  description = "KMS key ID for threat intelligence encryption"
  type        = string
  default     = null
}

variable "threat_intel_kms_key_arn" {
  description = "ARN of KMS key for threat intelligence encryption"
  type        = string
  default     = null
}

variable "threat_intel_update_schedule" {
  description = "Schedule expression for threat intelligence updates"
  type        = string
  default     = "rate(24 hours)"
}

# Cross-Region Variables
variable "enable_cross_region" {
  description = "Enable cross-region GuardDuty configuration"
  type        = bool
  default     = true
}

variable "cross_region_member_email" {
  description = "Email for cross-region member invitation"
  type        = string
  default     = null
}

variable "uk_government_threat_list_location_alternate" {
  description = "S3 location of UK government threat intelligence list in alternate region"
  type        = string
  default     = null
}

variable "ncsc_threat_list_location_alternate" {
  description = "S3 location of Security Standards threat intelligence list in alternate region"
  type        = string
  default     = null
}

variable "uk_government_allowlist_location_alternate" {
  description = "S3 location of UK government IP allowlist in alternate region"
  type        = string
  default     = null
}

variable "findings_destination_arn_alternate" {
  description = "ARN of the S3 bucket for GuardDuty findings in alternate region"
  type        = string
  default     = null
}

variable "findings_kms_key_arn_alternate" {
  description = "ARN of the KMS key for encrypting GuardDuty findings in alternate region"
  type        = string
  default     = null
}

variable "enable_cross_region_aggregation" {
  description = "Enable cross-region findings aggregation"
  type        = bool
  default     = true
}

variable "cross_region_findings_topic_arn" {
  description = "ARN of SNS topic for cross-region findings aggregation"
  type        = string
  default     = null
}

variable "enable_disaster_recovery" {
  description = "Enable disaster recovery GuardDuty configuration"
  type        = bool
  default     = false
}

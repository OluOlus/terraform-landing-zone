# KMS Module Variables
# Variables for UK-compliant encryption key management

# Core KMS Key Variables
variable "key_name" {
  description = "Name of the KMS key"
  type        = string
}

variable "key_alias" {
  description = "Alias for the KMS key (without alias/ prefix)"
  type        = string
}

variable "key_description" {
  description = "Description of the KMS key"
  type        = string
}

variable "key_purpose" {
  description = "Purpose of the KMS key"
  type        = string
  default     = "General encryption"
}

variable "key_usage" {
  description = "Intended use of the key (ENCRYPT_DECRYPT, SIGN_VERIFY, or GENERATE_VERIFY_MAC)"
  type        = string
  default     = "ENCRYPT_DECRYPT"
  validation {
    condition     = contains(["ENCRYPT_DECRYPT", "SIGN_VERIFY", "GENERATE_VERIFY_MAC"], var.key_usage)
    error_message = "Key usage must be ENCRYPT_DECRYPT, SIGN_VERIFY, or GENERATE_VERIFY_MAC."
  }
}

variable "customer_master_key_spec" {
  description = "Specification of the key material (SYMMETRIC_DEFAULT, RSA_2048, etc.)"
  type        = string
  default     = "SYMMETRIC_DEFAULT"
}

variable "deletion_window_in_days" {
  description = "Duration in days before key deletion (7-30 days)"
  type        = number
  default     = 30
  validation {
    condition     = var.deletion_window_in_days >= 7 && var.deletion_window_in_days <= 30
    error_message = "Deletion window must be between 7 and 30 days."
  }
}

variable "is_enabled" {
  description = "Enable the KMS key"
  type        = bool
  default     = true
}

variable "enable_key_rotation" {
  description = "Enable automatic key rotation (365 days for GDPR compliance)"
  type        = bool
  default     = true
}

variable "multi_region" {
  description = "Create a multi-region key"
  type        = bool
  default     = false
}

# Key Policy
variable "key_policy" {
  description = "Custom key policy JSON (if not provided, default policy will be used)"
  type        = string
  default     = null
}

# Service Access Permissions
variable "allow_cloudtrail_access" {
  description = "Allow CloudTrail to use the key for log encryption"
  type        = bool
  default     = false
}

variable "allow_cloudwatch_logs_access" {
  description = "Allow CloudWatch Logs to use the key"
  type        = bool
  default     = false
}

variable "allow_s3_access" {
  description = "Allow S3 to use the key for bucket encryption"
  type        = bool
  default     = false
}

variable "allow_config_access" {
  description = "Allow AWS Config to use the key"
  type        = bool
  default     = false
}

variable "allow_sns_access" {
  description = "Allow SNS to use the key for topic encryption"
  type        = bool
  default     = false
}

variable "allow_vpc_flow_logs_access" {
  description = "Allow VPC Flow Logs to use the key"
  type        = bool
  default     = false
}

# Organization and Additional Access
variable "organization_id" {
  description = "AWS Organization ID to grant access to all member accounts"
  type        = string
  default     = null
}

variable "additional_key_users" {
  description = "List of additional IAM principal ARNs that can use the key"
  type        = list(string)
  default     = []
}

# Service Grants
variable "service_grants" {
  description = "Map of KMS grants to create for services"
  type = map(object({
    grantee_principal = string
    operations        = list(string)
    constraints = object({
      encryption_context_equals = map(string)
      encryption_context_subset = map(string)
    })
  }))
  default = {}
}

# Monitoring
variable "enable_key_monitoring" {
  description = "Enable CloudWatch alarms for key monitoring"
  type        = bool
  default     = true
}

variable "alarm_sns_topic_arns" {
  description = "SNS topic ARNs for alarm notifications"
  type        = list(string)
  default     = []
}

# Multi-Region Replication
variable "create_replica_key" {
  description = "Create a replica key in another region"
  type        = bool
  default     = false
}

variable "replica_region" {
  description = "Region for replica key (e.g., us-west-2)"
  type        = string
  default     = "us-west-2"
}

# Common Tags
variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

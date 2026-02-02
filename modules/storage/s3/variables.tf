# S3 Module Variables
# Variables for UK-compliant S3 bucket configuration

# Core Bucket Variables
variable "bucket_name" {
  description = "Name of the S3 bucket"
  type        = string
}

variable "bucket_purpose" {
  description = "Purpose of the S3 bucket"
  type        = string
  default     = "General storage"
}

variable "data_classification" {
  description = "Data classification level (public, internal, confidential, restricted)"
  type        = string
  default     = "confidential"
  validation {
    condition     = contains(["public", "internal", "confidential", "restricted"], var.data_classification)
    error_message = "Data classification must be one of: public, internal, confidential, restricted."
  }
}

variable "force_destroy" {
  description = "Allow bucket deletion even if it contains objects"
  type        = bool
  default     = false
}

# Versioning
variable "enable_versioning" {
  description = "Enable bucket versioning"
  type        = bool
  default     = true
}

variable "enable_mfa_delete" {
  description = "Enable MFA delete for versioning"
  type        = bool
  default     = false
}

# Encryption
variable "kms_key_id" {
  description = "KMS key ID for bucket encryption (if null, uses AES256)"
  type        = string
  default     = null
}

# Public Access Block
variable "block_public_acls" {
  description = "Block public ACLs"
  type        = bool
  default     = true
}

variable "block_public_policy" {
  description = "Block public bucket policies"
  type        = bool
  default     = true
}

variable "ignore_public_acls" {
  description = "Ignore public ACLs"
  type        = bool
  default     = true
}

variable "restrict_public_buckets" {
  description = "Restrict public bucket policies"
  type        = bool
  default     = true
}

# Access Logging
variable "enable_access_logging" {
  description = "Enable S3 access logging"
  type        = bool
  default     = false
}

variable "access_logging_bucket_name" {
  description = "Target bucket for access logs"
  type        = string
  default     = null
}

variable "access_logging_prefix" {
  description = "Prefix for access log objects"
  type        = string
  default     = "access-logs/"
}

# Lifecycle Rules
variable "lifecycle_rules" {
  description = "List of lifecycle rules for the bucket"
  type = list(object({
    id     = string
    status = string
    filter = object({
      prefix = string
      tags   = map(string)
    })
    transitions = list(object({
      days          = number
      storage_class = string
    }))
    expiration = object({
      days                         = number
      expired_object_delete_marker = bool
    })
    noncurrent_version_expiration = object({
      noncurrent_days = number
    })
  }))
  default = []
}

# Bucket Policy
variable "bucket_policy" {
  description = "Custom bucket policy JSON"
  type        = string
  default     = null
}

variable "create_default_policy" {
  description = "Create a default secure bucket policy"
  type        = bool
  default     = true
}

variable "organization_id" {
  description = "AWS Organization ID for policy conditions"
  type        = string
  default     = null
}

variable "organization_allowed_actions" {
  description = "S3 actions allowed for organization accounts"
  type        = list(string)
  default = [
    "s3:GetObject",
    "s3:ListBucket"
  ]
}

# CORS Configuration
variable "cors_rules" {
  description = "CORS rules for the bucket"
  type = list(object({
    allowed_headers = list(string)
    allowed_methods = list(string)
    allowed_origins = list(string)
    expose_headers  = list(string)
    max_age_seconds = number
  }))
  default = []
}

# Object Lock
variable "enable_object_lock" {
  description = "Enable S3 Object Lock"
  type        = bool
  default     = false
}

variable "object_lock_mode" {
  description = "Object Lock retention mode (GOVERNANCE or COMPLIANCE)"
  type        = string
  default     = "GOVERNANCE"
  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.object_lock_mode)
    error_message = "Object lock mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "object_lock_retention_days" {
  description = "Number of days for Object Lock retention"
  type        = number
  default     = null
}

variable "object_lock_retention_years" {
  description = "Number of years for Object Lock retention"
  type        = number
  default     = null
}

# Replication
variable "enable_replication" {
  description = "Enable S3 replication"
  type        = bool
  default     = false
}

variable "replication_role_arn" {
  description = "IAM role ARN for replication"
  type        = string
  default     = null
}

variable "replication_rule_id" {
  description = "ID for the replication rule"
  type        = string
  default     = "replicate-all"
}

variable "replication_prefix" {
  description = "Prefix filter for replication"
  type        = string
  default     = ""
}

variable "replication_destination_bucket_arn" {
  description = "Destination bucket ARN for replication"
  type        = string
  default     = null
}

variable "replication_storage_class" {
  description = "Storage class for replicated objects"
  type        = string
  default     = "STANDARD"
}

variable "replication_kms_key_id" {
  description = "KMS key ID for replication destination encryption"
  type        = string
  default     = null
}

variable "enable_replication_time_control" {
  description = "Enable S3 Replication Time Control (RTC)"
  type        = bool
  default     = false
}

variable "replicate_delete_markers" {
  description = "Replicate delete markers"
  type        = bool
  default     = false
}

# Bucket Notifications
variable "enable_notifications" {
  description = "Enable S3 bucket notifications"
  type        = bool
  default     = false
}

variable "notification_lambda_configs" {
  description = "Lambda function notification configurations"
  type = list(object({
    function_arn  = string
    events        = list(string)
    filter_prefix = string
    filter_suffix = string
  }))
  default = []
}

variable "notification_sns_configs" {
  description = "SNS topic notification configurations"
  type = list(object({
    topic_arn     = string
    events        = list(string)
    filter_prefix = string
    filter_suffix = string
  }))
  default = []
}

variable "notification_sqs_configs" {
  description = "SQS queue notification configurations"
  type = list(object({
    queue_arn     = string
    events        = list(string)
    filter_prefix = string
    filter_suffix = string
  }))
  default = []
}

# Intelligent Tiering
variable "intelligent_tiering_configurations" {
  description = "Intelligent tiering configurations"
  type = map(object({
    status        = string
    filter_prefix = string
    filter_tags   = map(string)
    tierings = list(object({
      access_tier = string
      days        = number
    }))
  }))
  default = {}
}

# Monitoring
variable "enable_bucket_monitoring" {
  description = "Enable CloudWatch monitoring for bucket"
  type        = bool
  default     = false
}

variable "bucket_size_threshold_bytes" {
  description = "Bucket size threshold for CloudWatch alarm (bytes)"
  type        = number
  default     = 107374182400 # 100 GB
}

variable "alarm_sns_topic_arns" {
  description = "SNS topic ARNs for alarm notifications"
  type        = list(string)
  default     = []
}

# Common Tags
variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

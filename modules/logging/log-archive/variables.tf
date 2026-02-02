# Log Archive S3 Module Variables
# Variables for centralized UK log storage with GDPR compliance

# Primary Bucket Configuration
variable "primary_bucket_name" {
  description = "Name of the primary log archive S3 bucket"
  type        = string
}

variable "replica_bucket_name" {
  description = "Name of the replica log archive S3 bucket"
  type        = string
  default     = null
}

variable "force_destroy" {
  description = "Allow bucket deletion even if it contains objects"
  type        = bool
  default     = false
}

# Encryption Configuration
variable "primary_kms_key_id" {
  description = "KMS key ID for encrypting primary bucket"
  type        = string
}

variable "replica_kms_key_id" {
  description = "KMS key ID for encrypting replica bucket"
  type        = string
  default     = null
}

variable "enable_mfa_delete" {
  description = "Enable MFA delete for bucket versioning"
  type        = bool
  default     = false
}

# Access Logging Configuration
variable "enable_access_logging" {
  description = "Enable S3 access logging"
  type        = bool
  default     = true
}

variable "access_logging_bucket_name" {
  description = "S3 bucket for storing access logs"
  type        = string
  default     = null
}

# Lifecycle Policy Configuration - CloudTrail
variable "cloudtrail_transition_to_ia_days" {
  description = "Days before transitioning CloudTrail logs to IA"
  type        = number
  default     = 90
}

variable "cloudtrail_transition_to_glacier_days" {
  description = "Days before transitioning CloudTrail logs to Glacier"
  type        = number
  default     = 180
}

variable "cloudtrail_transition_to_deep_archive_days" {
  description = "Days before transitioning CloudTrail logs to Deep Archive"
  type        = number
  default     = 365
}

variable "cloudtrail_expiration_days" {
  description = "Days before expiring CloudTrail logs (7 years = 2555 days)"
  type        = number
  default     = 2555
}

# Lifecycle Policy Configuration - VPC Flow Logs
variable "flow_logs_transition_to_ia_days" {
  description = "Days before transitioning flow logs to IA"
  type        = number
  default     = 90
}

variable "flow_logs_transition_to_glacier_days" {
  description = "Days before transitioning flow logs to Glacier"
  type        = number
  default     = 180
}

variable "flow_logs_expiration_days" {
  description = "Days before expiring flow logs"
  type        = number
  default     = 2555 # 7 years
}

# Lifecycle Policy Configuration - Other Logs
variable "config_logs_expiration_days" {
  description = "Days before expiring Config logs"
  type        = number
  default     = 2555 # 7 years
}

variable "guardduty_findings_expiration_days" {
  description = "Days before expiring GuardDuty findings"
  type        = number
  default     = 2555 # 7 years
}

variable "securityhub_findings_expiration_days" {
  description = "Days before expiring Security Hub findings"
  type        = number
  default     = 2555 # 7 years
}

variable "network_firewall_logs_expiration_days" {
  description = "Days before expiring Network Firewall logs"
  type        = number
  default     = 2555 # 7 years
}

# Organization Configuration
variable "organization_id" {
  description = "AWS Organization ID for bucket policy"
  type        = string
}

# Cross-Region Replication
variable "enable_cross_region_replication" {
  description = "Enable cross-region replication for disaster recovery"
  type        = bool
  default     = true
}

variable "replication_role_arn" {
  description = "IAM role ARN for S3 replication"
  type        = string
  default     = null
}

variable "enable_replication_alarms" {
  description = "Enable CloudWatch alarms for replication monitoring"
  type        = bool
  default     = true
}

variable "alarm_sns_topic_arns" {
  description = "SNS topic ARNs for alarm notifications"
  type        = list(string)
  default     = []
}

# Bucket Notifications
variable "enable_bucket_notifications" {
  description = "Enable S3 bucket notifications"
  type        = bool
  default     = false
}

variable "notification_lambda_arns" {
  description = "Lambda function ARNs for bucket notifications"
  type        = list(string)
  default     = []
}

variable "notification_sns_topic_arns" {
  description = "SNS topic ARNs for bucket notifications"
  type        = list(string)
  default     = []
}

variable "notification_filter_prefix" {
  description = "S3 key prefix filter for notifications"
  type        = string
  default     = ""
}

variable "notification_filter_suffix" {
  description = "S3 key suffix filter for notifications"
  type        = string
  default     = ""
}

# Common Tags
variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

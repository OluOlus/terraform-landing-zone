# Variables for Log Retention Module

variable "project_name" {
  description = "Name of the project for resource naming"
  type        = string
  default     = "uk-landing-zone"
}

variable "common_tags" {
  description = "Common tags to be applied to all resources"
  type        = map(string)
  default = {
    Environment        = "shared"
    Project            = "uk-landing-zone"
    ManagedBy          = "Terraform"
    DataClassification = "confidential"
    Compliance         = "Security Standards-UK-GDPR"
  }
}

# CloudWatch Log Groups Configuration
variable "cloudwatch_log_groups" {
  description = "Map of CloudWatch log groups to manage retention for"
  type = map(object({
    name           = string
    retention_days = number
    kms_key_id     = optional(string)
    purpose        = string
  }))
  default = {}
}

# S3 Log Buckets Configuration
variable "s3_log_buckets" {
  description = "Map of S3 buckets containing logs to manage lifecycle for"
  type = map(object({
    bucket_name        = string
    replica_bucket_arn = optional(string)
    replica_kms_key_id = optional(string)
  }))
  default = {}
}

# CloudTrail Retention Settings (7 years = 2555 days)
variable "cloudtrail_retention_days" {
  description = "Number of days to retain CloudTrail logs (UK requirement: 7 years)"
  type        = number
  default     = 2555
  validation {
    condition     = var.cloudtrail_retention_days >= 2555
    error_message = "CloudTrail logs must be retained for at least 7 years (2555 days) for compliance."
  }
}

variable "cloudtrail_transition_to_ia_days" {
  description = "Number of days before transitioning CloudTrail logs to IA storage"
  type        = number
  default     = 30
}

variable "cloudtrail_transition_to_glacier_days" {
  description = "Number of days before transitioning CloudTrail logs to Glacier"
  type        = number
  default     = 90
}

variable "cloudtrail_transition_to_deep_archive_days" {
  description = "Number of days before transitioning CloudTrail logs to Deep Archive"
  type        = number
  default     = 365
}

# VPC Flow Logs Retention Settings (7 years = 2555 days)
variable "flow_logs_retention_days" {
  description = "Number of days to retain VPC Flow logs (UK requirement: 7 years)"
  type        = number
  default     = 2555
  validation {
    condition     = var.flow_logs_retention_days >= 2555
    error_message = "VPC Flow logs must be retained for at least 7 years (2555 days) for compliance."
  }
}

variable "flow_logs_transition_to_ia_days" {
  description = "Number of days before transitioning Flow logs to IA storage"
  type        = number
  default     = 30
}

variable "flow_logs_transition_to_glacier_days" {
  description = "Number of days before transitioning Flow logs to Glacier"
  type        = number
  default     = 90
}

# Config Logs Retention Settings (7 years = 2555 days)
variable "config_logs_retention_days" {
  description = "Number of days to retain AWS Config logs (UK requirement: 7 years)"
  type        = number
  default     = 2555
  validation {
    condition     = var.config_logs_retention_days >= 2555
    error_message = "Config logs must be retained for at least 7 years (2555 days) for compliance."
  }
}

# Security Findings Retention Settings (3 years = 1095 days)
variable "securityhub_findings_retention_days" {
  description = "Number of days to retain Security Hub findings"
  type        = number
  default     = 1095
}

variable "guardduty_findings_retention_days" {
  description = "Number of days to retain GuardDuty findings"
  type        = number
  default     = 1095
}

# Network Firewall Logs Retention Settings (1 year = 365 days)
variable "network_firewall_logs_retention_days" {
  description = "Number of days to retain Network Firewall logs"
  type        = number
  default     = 365
}

# Application Log Retention Rules
variable "application_log_retention_rules" {
  description = "Map of application-specific log retention rules"
  type = map(object({
    prefix          = string
    expiration_days = number
    transitions = list(object({
      days          = number
      storage_class = string
    }))
  }))
  default = {}
}

# Cross-Region Replication
variable "enable_cross_region_replication" {
  description = "Enable cross-region replication for critical logs"
  type        = bool
  default     = true
}

variable "replication_role_arn" {
  description = "ARN of the IAM role for S3 replication"
  type        = string
  default     = null
}

# Log Monitoring
variable "log_metric_filters" {
  description = "Map of CloudWatch log metric filters for monitoring"
  type = map(object({
    log_group_name   = string
    pattern          = string
    metric_name      = string
    metric_namespace = string
    metric_value     = string
  }))
  default = {}
}

variable "retention_compliance_alarms" {
  description = "Map of CloudWatch alarms for retention compliance monitoring"
  type = map(object({
    comparison_operator = string
    evaluation_periods  = number
    metric_name         = string
    namespace           = string
    period              = number
    statistic           = string
    threshold           = number
    description         = string
    alarm_actions       = list(string)
  }))
  default = {}
}

# Automated Cleanup
variable "enable_automated_cleanup" {
  description = "Enable automated log cleanup Lambda function"
  type        = bool
  default     = false
}

variable "default_log_retention_days" {
  description = "Default retention period for logs in days"
  type        = number
  default     = 2555
}

variable "cleanup_dry_run" {
  description = "Run cleanup in dry-run mode (no actual deletion)"
  type        = bool
  default     = true
}

variable "cleanup_schedule_expression" {
  description = "Schedule expression for automated cleanup (cron or rate)"
  type        = string
  default     = "rate(7 days)"
}
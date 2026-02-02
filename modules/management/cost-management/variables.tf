# Cost Management Module Variables

variable "budgets" {
  description = "Map of AWS budgets to create"
  type = map(object({
    budget_type       = string
    limit_amount      = string
    limit_unit        = string
    time_unit         = string
    time_period_start = string
    time_period_end   = string
    cost_filters      = map(list(string))
    notifications = list(object({
      comparison_operator        = string
      threshold                  = number
      threshold_type             = string
      notification_type          = string
      subscriber_email_addresses = list(string)
      subscriber_sns_topic_arns  = list(string)
    }))
  }))
  default = {}
}

variable "enable_anomaly_detection" {
  description = "Enable cost anomaly detection"
  type        = bool
  default     = true
}

variable "anomaly_monitor_name" {
  description = "Name of the cost anomaly monitor"
  type        = string
  default     = "uk-landing-zone-cost-anomalies"
}

variable "anomaly_monitor_type" {
  description = "Type of anomaly monitor (DIMENSIONAL or CUSTOM)"
  type        = string
  default     = "DIMENSIONAL"
}

variable "anomaly_monitor_dimension" {
  description = "Dimension for anomaly monitoring"
  type        = string
  default     = "SERVICE"
}

variable "anomaly_subscription_frequency" {
  description = "Frequency of anomaly notifications (DAILY, IMMEDIATE, or WEEKLY)"
  type        = string
  default     = "DAILY"
}

variable "anomaly_threshold_amount" {
  description = "Threshold amount for anomaly alerts (USD)"
  type        = number
  default     = 100
}

variable "anomaly_subscriber_emails" {
  description = "List of email addresses for anomaly notifications"
  type        = list(string)
  default     = []
}

variable "anomaly_subscriber_sns_arns" {
  description = "List of SNS topic ARNs for anomaly notifications"
  type        = list(string)
  default     = []
}

variable "enable_cost_usage_report" {
  description = "Enable Cost and Usage Report"
  type        = bool
  default     = false
}

variable "cur_report_name" {
  description = "Name of the Cost and Usage Report"
  type        = string
  default     = "uk-landing-zone-cur"
}

variable "cur_s3_bucket_name" {
  description = "S3 bucket for Cost and Usage Report"
  type        = string
  default     = null
}

variable "cur_s3_region" {
  description = "S3 bucket region for Cost and Usage Report"
  type        = string
  default     = "us-east-1"
}

variable "cur_s3_prefix" {
  description = "S3 prefix for Cost and Usage Report"
  type        = string
  default     = "cur/"
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

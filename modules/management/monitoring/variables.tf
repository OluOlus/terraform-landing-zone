# Variables for Monitoring Module

variable "environment" {
  description = "Environment name (e.g., production, staging, development)"
  type        = string
}

variable "aws_region" {
  description = "AWS region for monitoring resources"
  type        = string
  default     = "us-east-1"
}

variable "tags" {
  description = "Tags to apply to all monitoring resources"
  type        = map(string)
  default     = {}
}

variable "notification_email" {
  description = "Email address for security notifications"
  type        = string
  default     = ""
}

variable "enable_cost_monitoring" {
  description = "Enable cost monitoring dashboard"
  type        = bool
  default     = true
}

variable "enable_security_monitoring" {
  description = "Enable security monitoring dashboard"
  type        = bool
  default     = true
}

variable "enable_compliance_monitoring" {
  description = "Enable compliance monitoring dashboard"
  type        = bool
  default     = true
}

variable "alarm_threshold_critical_findings" {
  description = "Threshold for critical security findings alarm"
  type        = number
  default     = 10
}

variable "alarm_threshold_guardduty_findings" {
  description = "Threshold for GuardDuty findings alarm"
  type        = number
  default     = 0
}
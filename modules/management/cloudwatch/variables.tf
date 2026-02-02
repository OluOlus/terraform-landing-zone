# CloudWatch Monitoring Module Variables

variable "log_groups" {
  description = "Map of CloudWatch log groups to create"
  type = map(object({
    name           = string
    retention_days = number
    kms_key_id     = string
    purpose        = string
  }))
  default = {}
}

variable "metric_alarms" {
  description = "Map of CloudWatch metric alarms"
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
    ok_actions          = list(string)
    treat_missing_data  = string
    dimensions          = map(string)
  }))
  default = {}
}

variable "create_dashboard" {
  description = "Create CloudWatch dashboard"
  type        = bool
  default     = false
}

variable "dashboard_name" {
  description = "Name of the CloudWatch dashboard"
  type        = string
  default     = "uk-landing-zone-dashboard"
}

variable "dashboard_body" {
  description = "Dashboard body JSON"
  type        = any
  default     = null
}

variable "composite_alarms" {
  description = "Map of composite alarms"
  type = map(object({
    description   = string
    alarm_actions = list(string)
    ok_actions    = list(string)
    alarm_rule    = string
  }))
  default = {}
}

variable "event_rules" {
  description = "Map of CloudWatch event rules"
  type = map(object({
    description   = string
    event_pattern = any
    is_enabled    = bool
  }))
  default = {}
}

variable "event_targets" {
  description = "Map of event targets"
  type = map(object({
    rule_name  = string
    target_arn = string
    role_arn   = string
    input_transformer = object({
      input_paths    = map(string)
      input_template = string
    })
  }))
  default = {}
}

variable "create_sns_topic" {
  description = "Create SNS topic for alarms"
  type        = bool
  default     = true
}

variable "sns_topic_name" {
  description = "Name of SNS topic for alarms"
  type        = string
  default     = "cloudwatch-alarms"
}

variable "sns_kms_key_id" {
  description = "KMS key ID for SNS topic encryption"
  type        = string
  default     = null
}

variable "sns_subscriptions" {
  description = "Map of SNS subscriptions"
  type = map(object({
    protocol = string
    endpoint = string
  }))
  default = {}
}

variable "insights_queries" {
  description = "Map of CloudWatch Insights query definitions"
  type = map(object({
    query_string    = string
    log_group_names = list(string)
  }))
  default = {}
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

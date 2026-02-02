# CloudWatch Monitoring Module Outputs

output "log_group_arns" {
  description = "Map of log group names to ARNs"
  value       = { for k, v in aws_cloudwatch_log_group.log_groups : k => v.arn }
}

output "metric_alarm_arns" {
  description = "Map of metric alarm names to ARNs"
  value       = { for k, v in aws_cloudwatch_metric_alarm.alarms : k => v.arn }
}

output "dashboard_arn" {
  description = "ARN of the CloudWatch dashboard"
  value       = var.create_dashboard ? aws_cloudwatch_dashboard.main[0].dashboard_arn : null
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for alarms"
  value       = var.create_sns_topic ? aws_sns_topic.alarms[0].arn : null
}

output "event_rule_arns" {
  description = "Map of event rule names to ARNs"
  value       = { for k, v in aws_cloudwatch_event_rule.rules : k => v.arn }
}

# Outputs for Monitoring Module

output "security_posture_dashboard_url" {
  description = "URL for the security posture dashboard"
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.security_posture.dashboard_name}"
}

output "compliance_dashboard_url" {
  description = "URL for the compliance dashboard"
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.compliance.dashboard_name}"
}

output "cost_usage_dashboard_url" {
  description = "URL for the cost usage dashboard"
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.cost_usage.dashboard_name}"
}

output "security_alerts_topic_arn" {
  description = "ARN of the security alerts SNS topic"
  value       = aws_sns_topic.security_alerts.arn
}

output "security_hub_alarm_name" {
  description = "Name of the Security Hub critical findings alarm"
  value       = aws_cloudwatch_metric_alarm.security_hub_critical_findings.alarm_name
}

output "guardduty_alarm_name" {
  description = "Name of the GuardDuty findings alarm"
  value       = aws_cloudwatch_metric_alarm.guardduty_findings.alarm_name
}

output "dashboard_names" {
  description = "List of all dashboard names"
  value = [
    aws_cloudwatch_dashboard.security_posture.dashboard_name,
    aws_cloudwatch_dashboard.compliance.dashboard_name,
    aws_cloudwatch_dashboard.cost_usage.dashboard_name
  ]
}
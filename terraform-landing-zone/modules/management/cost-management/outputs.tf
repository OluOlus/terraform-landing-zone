# Cost Management Module Outputs

output "budget_arns" {
  description = "Map of budget names to ARNs"
  value       = { for k, v in aws_budgets_budget.budgets : k => v.arn }
}

output "anomaly_monitor_arn" {
  description = "ARN of the cost anomaly monitor"
  value       = var.enable_anomaly_detection ? aws_ce_anomaly_monitor.main[0].arn : null
}

output "anomaly_subscription_arn" {
  description = "ARN of the anomaly subscription"
  value       = var.enable_anomaly_detection ? aws_ce_anomaly_subscription.main[0].arn : null
}

output "cur_report_arn" {
  description = "ARN of the Cost and Usage Report"
  value       = var.enable_cost_usage_report ? aws_cur_report_definition.main[0].arn : null
}

output "configuration_summary" {
  description = "Summary of cost management configuration"
  value = {
    budgets_count     = length(var.budgets)
    anomaly_detection = var.enable_anomaly_detection
    cost_usage_report = var.enable_cost_usage_report
  }
}

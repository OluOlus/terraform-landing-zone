output "instance_arn" {
  description = "IAM Identity Center instance ARN"
  value       = local.instance_arn
}

output "identity_store_id" {
  description = "Identity Store ID"
  value       = local.identity_store_id
}

output "security_admin_permission_set_arn" {
  description = "Security Admin permission set ARN"
  value       = aws_ssoadmin_permission_set.security_admin.arn
}

output "network_admin_permission_set_arn" {
  description = "Network Admin permission set ARN"
  value       = aws_ssoadmin_permission_set.network_admin.arn
}

output "developer_permission_set_arn" {
  description = "Developer permission set ARN"
  value       = aws_ssoadmin_permission_set.developer.arn
}

output "viewer_permission_set_arn" {
  description = "Viewer permission set ARN"
  value       = aws_ssoadmin_permission_set.viewer.arn
}

output "break_glass_permission_set_arn" {
  description = "Break Glass Emergency permission set ARN"
  value       = aws_ssoadmin_permission_set.break_glass.arn
}

output "permission_sets" {
  description = "Map of all permission set names to their ARNs"
  value = {
    SecurityAdministrator = aws_ssoadmin_permission_set.security_admin.arn
    NetworkAdministrator  = aws_ssoadmin_permission_set.network_admin.arn
    Developer             = aws_ssoadmin_permission_set.developer.arn
    ReadOnlyViewer        = aws_ssoadmin_permission_set.viewer.arn
    BreakGlassEmergency   = aws_ssoadmin_permission_set.break_glass.arn
  }
}

output "break_glass_monitoring" {
  description = "Break glass monitoring configuration"
  value = var.enable_break_glass_monitoring ? {
    metric_filter_name = aws_cloudwatch_log_metric_filter.break_glass_usage[0].name
    alarm_name         = aws_cloudwatch_metric_alarm.break_glass_usage[0].alarm_name
    alarm_arn          = aws_cloudwatch_metric_alarm.break_glass_usage[0].arn
  } : null
}

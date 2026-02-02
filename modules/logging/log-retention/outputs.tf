# Outputs for Log Retention Module

# CloudWatch Log Groups
output "cloudwatch_log_groups" {
  description = "Map of managed CloudWatch log groups"
  value = {
    for k, v in aws_cloudwatch_log_group.retention_managed_groups : k => {
      name              = v.name
      arn               = v.arn
      retention_in_days = v.retention_in_days
      kms_key_id        = v.kms_key_id
    }
  }
}

# S3 Lifecycle Configurations
output "s3_lifecycle_configurations" {
  description = "Map of S3 bucket lifecycle configurations"
  value = {
    for k, v in aws_s3_bucket_lifecycle_configuration.log_retention : k => {
      bucket = v.bucket
      id     = v.id
    }
  }
}

# Replication Configurations
output "replication_configurations" {
  description = "Map of S3 bucket replication configurations"
  value = var.enable_cross_region_replication ? {
    for k, v in aws_s3_bucket_replication_configuration.log_replication : k => {
      bucket = v.bucket
      role   = v.role
    }
  } : {}
}

# CloudWatch Metric Filters
output "metric_filters" {
  description = "Map of CloudWatch log metric filters"
  value = {
    for k, v in aws_cloudwatch_log_metric_filter.retention_monitoring : k => {
      name           = v.name
      log_group_name = v.log_group_name
      pattern        = v.pattern
    }
  }
}

# CloudWatch Alarms
output "retention_alarms" {
  description = "Map of retention compliance CloudWatch alarms"
  value = {
    for k, v in aws_cloudwatch_metric_alarm.retention_compliance : k => {
      alarm_name = v.alarm_name
      arn        = v.arn
    }
  }
}

# Lambda Function (if enabled)
output "cleanup_lambda_function" {
  description = "Log cleanup Lambda function details"
  value = var.enable_automated_cleanup ? {
    function_name = aws_lambda_function.log_cleanup[0].function_name
    arn           = aws_lambda_function.log_cleanup[0].arn
    role_arn      = aws_iam_role.log_cleanup[0].arn
  } : null
}

# EventBridge Rule (if enabled)
output "cleanup_schedule_rule" {
  description = "EventBridge rule for log cleanup schedule"
  value = var.enable_automated_cleanup ? {
    name                = aws_cloudwatch_event_rule.log_cleanup_schedule[0].name
    arn                 = aws_cloudwatch_event_rule.log_cleanup_schedule[0].arn
    schedule_expression = aws_cloudwatch_event_rule.log_cleanup_schedule[0].schedule_expression
  } : null
}

# Retention Summary
output "retention_summary" {
  description = "Summary of retention policies applied"
  value = {
    cloudtrail_retention_days            = var.cloudtrail_retention_days
    flow_logs_retention_days             = var.flow_logs_retention_days
    config_logs_retention_days           = var.config_logs_retention_days
    securityhub_findings_retention_days  = var.securityhub_findings_retention_days
    guardduty_findings_retention_days    = var.guardduty_findings_retention_days
    network_firewall_logs_retention_days = var.network_firewall_logs_retention_days
    cross_region_replication_enabled     = var.enable_cross_region_replication
    automated_cleanup_enabled            = var.enable_automated_cleanup
  }
}
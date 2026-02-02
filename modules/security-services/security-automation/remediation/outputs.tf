output "remediation_lambda_role_arn" {
  description = "IAM role ARN for remediation Lambda functions"
  value       = aws_iam_role.remediation_lambda_role.arn
}

output "remediation_lambda_role_name" {
  description = "IAM role name for remediation Lambda functions"
  value       = aws_iam_role.remediation_lambda_role.name
}

# S3 Public Access Remediation Outputs
output "s3_public_access_remediation_arn" {
  description = "S3 public access remediation Lambda function ARN"
  value       = var.enable_s3_public_access_remediation ? aws_lambda_function.s3_public_access_remediation[0].arn : null
}

output "s3_public_access_remediation_name" {
  description = "S3 public access remediation Lambda function name"
  value       = var.enable_s3_public_access_remediation ? aws_lambda_function.s3_public_access_remediation[0].function_name : null
}

# Unencrypted Volumes Remediation Outputs
output "unencrypted_volumes_remediation_arn" {
  description = "Unencrypted volumes remediation Lambda function ARN"
  value       = var.enable_unencrypted_volumes_remediation ? aws_lambda_function.unencrypted_volumes_remediation[0].arn : null
}

output "unencrypted_volumes_remediation_name" {
  description = "Unencrypted volumes remediation Lambda function name"
  value       = var.enable_unencrypted_volumes_remediation ? aws_lambda_function.unencrypted_volumes_remediation[0].function_name : null
}

# Untagged Resources Remediation Outputs
output "untagged_resources_remediation_arn" {
  description = "Untagged resources remediation Lambda function ARN"
  value       = var.enable_untagged_resources_remediation ? aws_lambda_function.untagged_resources_remediation[0].arn : null
}

output "untagged_resources_remediation_name" {
  description = "Untagged resources remediation Lambda function name"
  value       = var.enable_untagged_resources_remediation ? aws_lambda_function.untagged_resources_remediation[0].function_name : null
}

# Orchestrator Function Outputs
output "security_hub_orchestrator_arn" {
  description = "Security Hub orchestrator Lambda function ARN"
  value       = aws_lambda_function.security_hub_orchestrator.arn
}

output "security_hub_orchestrator_name" {
  description = "Security Hub orchestrator Lambda function name"
  value       = aws_lambda_function.security_hub_orchestrator.function_name
}

output "guardduty_orchestrator_arn" {
  description = "GuardDuty orchestrator Lambda function ARN"
  value       = aws_lambda_function.guardduty_orchestrator.arn
}

output "guardduty_orchestrator_name" {
  description = "GuardDuty orchestrator Lambda function name"
  value       = aws_lambda_function.guardduty_orchestrator.function_name
}

output "config_orchestrator_arn" {
  description = "Config orchestrator Lambda function ARN"
  value       = aws_lambda_function.config_orchestrator.arn
}

output "config_orchestrator_name" {
  description = "Config orchestrator Lambda function name"
  value       = aws_lambda_function.config_orchestrator.function_name
}

# CloudWatch Alarms Outputs
output "cloudwatch_alarms" {
  description = "CloudWatch alarms for remediation functions"
  value = {
    s3_remediation_failures      = var.enable_s3_public_access_remediation ? aws_cloudwatch_metric_alarm.s3_remediation_failures[0].arn : null
    s3_remediation_duration      = var.enable_s3_public_access_remediation ? aws_cloudwatch_metric_alarm.s3_remediation_duration[0].arn : null
    volumes_remediation_failures = var.enable_unencrypted_volumes_remediation ? aws_cloudwatch_metric_alarm.volumes_remediation_failures[0].arn : null
    volumes_remediation_duration = var.enable_unencrypted_volumes_remediation ? aws_cloudwatch_metric_alarm.volumes_remediation_duration[0].arn : null
    tagging_remediation_failures = var.enable_untagged_resources_remediation ? aws_cloudwatch_metric_alarm.tagging_remediation_failures[0].arn : null
    tagging_remediation_duration = var.enable_untagged_resources_remediation ? aws_cloudwatch_metric_alarm.tagging_remediation_duration[0].arn : null
  }
}

# Dashboard Widgets Outputs
output "dashboard_widgets" {
  description = "CloudWatch dashboard widgets for remediation metrics"
  value = {
    s3_remediation      = var.enable_s3_public_access_remediation ? local.s3_remediation_dashboard_widget : null
    volumes_remediation = var.enable_unencrypted_volumes_remediation ? local.volumes_remediation_dashboard_widget : null
    tagging_remediation = var.enable_untagged_resources_remediation ? local.tagging_remediation_dashboard_widget : null
  }
}

# Metric Filters Outputs
output "metric_filters" {
  description = "CloudWatch log metric filters"
  value = {
    s3_success      = var.enable_s3_public_access_remediation ? aws_cloudwatch_log_metric_filter.s3_remediation_success[0].name : null
    s3_failure      = var.enable_s3_public_access_remediation ? aws_cloudwatch_log_metric_filter.s3_remediation_failure[0].name : null
    volumes_success = var.enable_unencrypted_volumes_remediation ? aws_cloudwatch_log_metric_filter.volumes_remediation_success[0].name : null
    volumes_failure = var.enable_unencrypted_volumes_remediation ? aws_cloudwatch_log_metric_filter.volumes_remediation_failure[0].name : null
    tagging_success = var.enable_untagged_resources_remediation ? aws_cloudwatch_log_metric_filter.tagging_remediation_success[0].name : null
    tagging_failure = var.enable_untagged_resources_remediation ? aws_cloudwatch_log_metric_filter.tagging_remediation_failure[0].name : null
  }
}

# Config Rules Outputs
output "config_rules" {
  description = "AWS Config rules for compliance monitoring"
  value = {
    uk_mandatory_tagging = var.enable_untagged_resources_remediation ? aws_config_config_rule.uk_mandatory_tagging[0].name : null
  }
}

# Remediation Summary
output "remediation_summary" {
  description = "Summary of all remediation capabilities"
  value = {
    enabled_remediations = {
      s3_public_access    = var.enable_s3_public_access_remediation
      unencrypted_volumes = var.enable_unencrypted_volumes_remediation
      untagged_resources  = var.enable_untagged_resources_remediation
    }
    lambda_functions = {
      s3_remediation            = var.enable_s3_public_access_remediation ? aws_lambda_function.s3_public_access_remediation[0].function_name : null
      volumes_remediation       = var.enable_unencrypted_volumes_remediation ? aws_lambda_function.unencrypted_volumes_remediation[0].function_name : null
      tagging_remediation       = var.enable_untagged_resources_remediation ? aws_lambda_function.untagged_resources_remediation[0].function_name : null
      security_hub_orchestrator = aws_lambda_function.security_hub_orchestrator.function_name
      guardduty_orchestrator    = aws_lambda_function.guardduty_orchestrator.function_name
      config_orchestrator       = aws_lambda_function.config_orchestrator.function_name
    }
    monitoring = {
      cloudwatch_alarms_count = length([
        for alarm in values(local.cloudwatch_alarms) : alarm if alarm != null
      ])
      metric_filters_count = length([
        for filter in values(local.metric_filters) : filter if filter != null
      ])
    }
  }
}

# Local values for internal calculations
locals {
  cloudwatch_alarms = {
    s3_failures      = var.enable_s3_public_access_remediation ? aws_cloudwatch_metric_alarm.s3_remediation_failures[0].arn : null
    s3_duration      = var.enable_s3_public_access_remediation ? aws_cloudwatch_metric_alarm.s3_remediation_duration[0].arn : null
    volumes_failures = var.enable_unencrypted_volumes_remediation ? aws_cloudwatch_metric_alarm.volumes_remediation_failures[0].arn : null
    volumes_duration = var.enable_unencrypted_volumes_remediation ? aws_cloudwatch_metric_alarm.volumes_remediation_duration[0].arn : null
    tagging_failures = var.enable_untagged_resources_remediation ? aws_cloudwatch_metric_alarm.tagging_remediation_failures[0].arn : null
    tagging_duration = var.enable_untagged_resources_remediation ? aws_cloudwatch_metric_alarm.tagging_remediation_duration[0].arn : null
  }

  metric_filters = {
    s3_success      = var.enable_s3_public_access_remediation ? aws_cloudwatch_log_metric_filter.s3_remediation_success[0].name : null
    s3_failure      = var.enable_s3_public_access_remediation ? aws_cloudwatch_log_metric_filter.s3_remediation_failure[0].name : null
    volumes_success = var.enable_unencrypted_volumes_remediation ? aws_cloudwatch_log_metric_filter.volumes_remediation_success[0].name : null
    volumes_failure = var.enable_unencrypted_volumes_remediation ? aws_cloudwatch_log_metric_filter.volumes_remediation_failure[0].name : null
    tagging_success = var.enable_untagged_resources_remediation ? aws_cloudwatch_log_metric_filter.tagging_remediation_success[0].name : null
    tagging_failure = var.enable_untagged_resources_remediation ? aws_cloudwatch_log_metric_filter.tagging_remediation_failure[0].name : null
  }
}
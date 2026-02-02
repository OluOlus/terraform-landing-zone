output "security_automation_kms_key_id" {
  description = "KMS key ID for Security Automation encryption"
  value       = aws_kms_key.security_automation.key_id
}

output "security_automation_kms_key_arn" {
  description = "KMS key ARN for Security Automation encryption"
  value       = aws_kms_key.security_automation.arn
}

output "remediation_artifacts_bucket_name" {
  description = "S3 bucket name for remediation artifacts"
  value       = aws_s3_bucket.remediation_artifacts.bucket
}

output "remediation_artifacts_bucket_arn" {
  description = "S3 bucket ARN for remediation artifacts"
  value       = aws_s3_bucket.remediation_artifacts.arn
}

output "security_automation_log_group_name" {
  description = "CloudWatch log group name for security automation"
  value       = aws_cloudwatch_log_group.security_automation.name
}

output "security_automation_log_group_arn" {
  description = "CloudWatch log group ARN for security automation"
  value       = aws_cloudwatch_log_group.security_automation.arn
}

output "security_automation_sns_topic_arn" {
  description = "SNS topic ARN for security automation notifications"
  value       = aws_sns_topic.security_automation_notifications.arn
}

output "eventbridge_rules" {
  description = "EventBridge rules for security automation"
  value = {
    security_hub_findings = aws_cloudwatch_event_rule.security_hub_findings.arn
    guardduty_findings    = aws_cloudwatch_event_rule.guardduty_findings.arn
    config_compliance     = aws_cloudwatch_event_rule.config_compliance.arn
  }
}

# Remediation function outputs
output "s3_public_access_remediation_arn" {
  description = "S3 public access remediation Lambda function ARN"
  value       = module.remediation_functions.s3_public_access_remediation_arn
}

output "unencrypted_volumes_remediation_arn" {
  description = "Unencrypted volumes remediation Lambda function ARN"
  value       = module.remediation_functions.unencrypted_volumes_remediation_arn
}

output "untagged_resources_remediation_arn" {
  description = "Untagged resources remediation Lambda function ARN"
  value       = module.remediation_functions.untagged_resources_remediation_arn
}

output "security_hub_orchestrator_arn" {
  description = "Security Hub orchestrator Lambda function ARN"
  value       = module.remediation_functions.security_hub_orchestrator_arn
}

output "guardduty_orchestrator_arn" {
  description = "GuardDuty orchestrator Lambda function ARN"
  value       = module.remediation_functions.guardduty_orchestrator_arn
}

output "config_orchestrator_arn" {
  description = "Config orchestrator Lambda function ARN"
  value       = module.remediation_functions.config_orchestrator_arn
}

output "remediation_functions_summary" {
  description = "Summary of all remediation functions"
  value = {
    s3_public_access = {
      arn     = module.remediation_functions.s3_public_access_remediation_arn
      name    = module.remediation_functions.s3_public_access_remediation_name
      enabled = var.enable_s3_public_access_remediation
    }
    unencrypted_volumes = {
      arn     = module.remediation_functions.unencrypted_volumes_remediation_arn
      name    = module.remediation_functions.unencrypted_volumes_remediation_name
      enabled = var.enable_unencrypted_volumes_remediation
    }
    untagged_resources = {
      arn     = module.remediation_functions.untagged_resources_remediation_arn
      name    = module.remediation_functions.untagged_resources_remediation_name
      enabled = var.enable_untagged_resources_remediation
    }
    orchestrators = {
      security_hub = {
        arn  = module.remediation_functions.security_hub_orchestrator_arn
        name = module.remediation_functions.security_hub_orchestrator_name
      }
      guardduty = {
        arn  = module.remediation_functions.guardduty_orchestrator_arn
        name = module.remediation_functions.guardduty_orchestrator_name
      }
      config = {
        arn  = module.remediation_functions.config_orchestrator_arn
        name = module.remediation_functions.config_orchestrator_name
      }
    }
  }
}

output "compliance_configuration" {
  description = "Compliance configuration summary"
  value = {
    ncsc_compliance_mode             = var.ncsc_compliance_mode
    uk_gdpr_compliance_mode          = var.uk_gdpr_compliance_mode
    cyber_essentials_compliance_mode = var.cyber_essentials_compliance_mode
    mandatory_uk_tags                = var.mandatory_uk_tags
    uk_data_classification_tags      = var.uk_data_classification_tags
    remediation_dry_run              = var.remediation_dry_run
    manual_approval_enabled          = var.enable_manual_approval
    compliance_reporting_enabled     = var.enable_compliance_reporting
  }
}

output "automation_configuration" {
  description = "Security automation configuration summary"
  value = {
    remediation_severity_levels      = var.remediation_severity_levels
    guardduty_remediation_severities = var.guardduty_remediation_severities
    lambda_timeout                   = var.lambda_timeout
    lambda_memory_size               = var.lambda_memory_size
    cross_account_remediation        = var.enable_cross_account_remediation
    trusted_accounts                 = var.trusted_remediation_accounts
    cost_optimization_enabled        = var.enable_cost_optimization
  }
}

output "monitoring_configuration" {
  description = "Monitoring and alerting configuration"
  value = {
    cloudwatch_log_retention_days  = var.cloudwatch_log_retention_days
    remediation_log_retention_days = var.remediation_log_retention_days
    notification_email             = var.notification_email
    compliance_report_frequency    = var.compliance_report_frequency
    approval_timeout_minutes       = var.approval_timeout_minutes
  }
}
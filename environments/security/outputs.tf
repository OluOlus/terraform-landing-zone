# Security Environment Outputs

output "security_hub_arn" {
  description = "ARN of the Security Hub"
  value       = module.security_hub.hub_arn
}

output "guardduty_detector_id" {
  description = "ID of the GuardDuty detector"
  value       = module.guardduty.detector_id
}

output "config_recorder_id" {
  description = "ID of the AWS Config recorder"
  value       = module.config.recorder_id
}

output "security_alerts_sns_topic_arn" {
  description = "ARN of the SNS topic for security alerts"
  value       = module.cloudwatch.sns_topic_arn
}

output "kms_security_key_arn" {
  description = "ARN of the KMS key for security services"
  value       = module.kms_security.key_arn
}

output "access_analyzer_arn" {
  description = "ARN of the IAM Access Analyzer"
  value       = aws_accessanalyzer_analyzer.organization.arn
}

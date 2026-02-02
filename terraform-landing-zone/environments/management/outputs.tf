# Management Environment Outputs

output "organization_id" {
  description = "AWS Organization ID"
  value       = module.management_account.organization_id
}

output "management_account_id" {
  description = "Management account ID"
  value       = data.aws_caller_identity.current.account_id
}

output "identity_center_instance_arn" {
  description = "IAM Identity Center instance ARN"
  value       = module.identity_center.instance_arn
}

output "cloudwatch_sns_topic_arn" {
  description = "SNS topic ARN for CloudWatch alarms"
  value       = module.cloudwatch.sns_topic_arn
}

output "kms_cloudtrail_key_arn" {
  description = "KMS key ARN for CloudTrail"
  value       = module.kms_cloudtrail.key_arn
}

output "kms_logs_key_arn" {
  description = "KMS key ARN for CloudWatch Logs"
  value       = module.kms_logs.key_arn
}

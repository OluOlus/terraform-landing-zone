# Outputs for Management Account Module

output "organization_id" {
  description = "The ID of the AWS Organization"
  value       = aws_organizations_organization.main.id
}

output "organization_arn" {
  description = "The ARN of the AWS Organization"
  value       = aws_organizations_organization.main.arn
}

output "organization_root_id" {
  description = "The ID of the organization root"
  value       = aws_organizations_organization.main.roots[0].id
}

output "organization_master_account_id" {
  description = "The ID of the organization master account"
  value       = aws_organizations_organization.main.master_account_id
}

output "organization_master_account_arn" {
  description = "The ARN of the organization master account"
  value       = aws_organizations_organization.main.master_account_arn
}

output "organization_master_account_email" {
  description = "The email address of the organization master account"
  value       = aws_organizations_organization.main.master_account_email
}

output "current_account_id" {
  description = "The current AWS account ID (Management Account)"
  value       = data.aws_caller_identity.current.account_id
}

# Note: OU and SCP outputs are now in the organization module

# Config outputs
output "config_recorder_name" {
  description = "The name of the Config configuration recorder"
  value       = aws_config_configuration_recorder.management.name
}

output "config_delivery_channel_name" {
  description = "The name of the Config delivery channel"
  value       = aws_config_delivery_channel.management.name
}

output "config_s3_bucket_name" {
  description = "The name of the S3 bucket for Config"
  value       = aws_s3_bucket.config.bucket
}

output "config_s3_bucket_arn" {
  description = "The ARN of the S3 bucket for Config"
  value       = aws_s3_bucket.config.arn
}

output "config_kms_key_id" {
  description = "The ID of the KMS key for Config encryption"
  value       = aws_kms_key.config.id
}

output "config_kms_key_arn" {
  description = "The ARN of the KMS key for Config encryption"
  value       = aws_kms_key.config.arn
}

output "config_kms_alias_name" {
  description = "The name of the KMS key alias for Config encryption"
  value       = aws_kms_alias.config.name
}

output "config_iam_role_name" {
  description = "The name of the IAM role for Config"
  value       = aws_iam_role.config.name
}

output "config_iam_role_arn" {
  description = "The ARN of the IAM role for Config"
  value       = aws_iam_role.config.arn
}
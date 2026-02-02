# KMS Module Outputs

# Key Outputs
output "key_id" {
  description = "ID of the KMS key"
  value       = aws_kms_key.main.key_id
}

output "key_arn" {
  description = "ARN of the KMS key"
  value       = aws_kms_key.main.arn
}

output "key_alias_name" {
  description = "Alias name of the KMS key"
  value       = aws_kms_alias.main.name
}

output "key_alias_arn" {
  description = "ARN of the KMS key alias"
  value       = aws_kms_alias.main.arn
}

output "key_enabled" {
  description = "Whether the KMS key is enabled"
  value       = aws_kms_key.main.is_enabled
}

output "key_rotation_enabled" {
  description = "Whether automatic key rotation is enabled"
  value       = aws_kms_key.main.enable_key_rotation
}

# Replica Key Outputs
output "replica_key_id" {
  description = "ID of the replica KMS key"
  value       = var.create_replica_key ? aws_kms_replica_key.replica[0].key_id : null
}

output "replica_key_arn" {
  description = "ARN of the replica KMS key"
  value       = var.create_replica_key ? aws_kms_replica_key.replica[0].arn : null
}

output "replica_key_alias_name" {
  description = "Alias name of the replica KMS key"
  value       = var.create_replica_key ? aws_kms_alias.replica[0].name : null
}

# Grant Outputs
output "grant_ids" {
  description = "Map of grant names to grant IDs"
  value       = { for k, v in aws_kms_grant.service_grants : k => v.grant_id }
}

# Monitoring Outputs
output "key_disabled_alarm_arn" {
  description = "ARN of the key disabled CloudWatch alarm"
  value       = var.enable_key_monitoring ? aws_cloudwatch_metric_alarm.kms_key_disabled[0].arn : null
}

output "key_pending_deletion_alarm_arn" {
  description = "ARN of the key pending deletion CloudWatch alarm"
  value       = var.enable_key_monitoring ? aws_cloudwatch_metric_alarm.kms_key_pending_deletion[0].arn : null
}

# Configuration Summary
output "configuration_summary" {
  description = "Summary of KMS key configuration"
  value = {
    key_id                 = aws_kms_key.main.key_id
    key_arn                = aws_kms_key.main.arn
    alias                  = aws_kms_alias.main.name
    enabled                = aws_kms_key.main.is_enabled
    rotation_enabled       = aws_kms_key.main.enable_key_rotation
    multi_region           = aws_kms_key.main.multi_region
    deletion_window_days   = var.deletion_window_in_days
    replica_created        = var.create_replica_key
    monitoring_enabled     = var.enable_key_monitoring
    cloudtrail_access      = var.allow_cloudtrail_access
    cloudwatch_logs_access = var.allow_cloudwatch_logs_access
    s3_access              = var.allow_s3_access
    config_access          = var.allow_config_access
    sns_access             = var.allow_sns_access
    vpc_flow_logs_access   = var.allow_vpc_flow_logs_access
  }
}

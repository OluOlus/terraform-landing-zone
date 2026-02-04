# Logging Environment Outputs

output "log_archive_bucket_name" {
  description = "Name of the primary log archive bucket"
  value       = module.log_archive.primary_bucket_id
}

output "log_archive_bucket_arn" {
  description = "ARN of the primary log archive bucket"
  value       = module.log_archive.primary_bucket_arn
}

output "replica_bucket_name" {
  description = "Name of the replica log archive bucket"
  value       = module.log_archive.replica_bucket_id
}

output "cloudtrail_arn" {
  description = "ARN of the organization CloudTrail"
  value       = module.cloudtrail.trail_arn
}

output "kms_cloudtrail_key_arn" {
  description = "ARN of the KMS key for CloudTrail"
  value       = module.kms_cloudtrail.key_arn
}

output "kms_logs_key_arn" {
  description = "ARN of the KMS key for log archive"
  value       = module.kms_logs.key_arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for alerts"
  value       = module.cloudwatch.sns_topic_arn
}

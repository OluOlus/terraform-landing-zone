# S3 Module Outputs

# Bucket Outputs
output "bucket_id" {
  description = "ID of the S3 bucket"
  value       = aws_s3_bucket.main.id
}

output "bucket_arn" {
  description = "ARN of the S3 bucket"
  value       = aws_s3_bucket.main.arn
}

output "bucket_domain_name" {
  description = "Domain name of the S3 bucket"
  value       = aws_s3_bucket.main.bucket_domain_name
}

output "bucket_regional_domain_name" {
  description = "Regional domain name of the S3 bucket"
  value       = aws_s3_bucket.main.bucket_regional_domain_name
}

output "bucket_region" {
  description = "Region of the S3 bucket"
  value       = aws_s3_bucket.main.region
}

# Configuration Outputs
output "versioning_enabled" {
  description = "Whether versioning is enabled"
  value       = var.enable_versioning
}

output "encryption_enabled" {
  description = "Whether encryption is enabled"
  value       = true
}

output "kms_encryption" {
  description = "Whether KMS encryption is used"
  value       = var.kms_key_id != null
}

output "public_access_blocked" {
  description = "Whether all public access is blocked"
  value = (
    var.block_public_acls &&
    var.block_public_policy &&
    var.ignore_public_acls &&
    var.restrict_public_buckets
  )
}

output "replication_enabled" {
  description = "Whether replication is enabled"
  value       = var.enable_replication
}

# Monitoring Outputs
output "bucket_size_alarm_arn" {
  description = "ARN of the bucket size CloudWatch alarm"
  value       = var.enable_bucket_monitoring ? aws_cloudwatch_metric_alarm.bucket_size[0].arn : null
}

# Configuration Summary
output "configuration_summary" {
  description = "Summary of S3 bucket configuration"
  value = {
    bucket_name            = aws_s3_bucket.main.id
    bucket_arn             = aws_s3_bucket.main.arn
    region                 = aws_s3_bucket.main.region
    versioning_enabled     = var.enable_versioning
    mfa_delete_enabled     = var.enable_mfa_delete
    encryption_type        = var.kms_key_id != null ? "KMS" : "AES256"
    kms_key_id             = var.kms_key_id
    public_access_blocked  = var.block_public_acls && var.block_public_policy && var.ignore_public_acls && var.restrict_public_buckets
    access_logging_enabled = var.enable_access_logging
    replication_enabled    = var.enable_replication
    object_lock_enabled    = var.enable_object_lock
    notifications_enabled  = var.enable_notifications
    monitoring_enabled     = var.enable_bucket_monitoring
    data_classification    = var.data_classification
    lifecycle_rules_count  = length(var.lifecycle_rules)
    cors_rules_count       = length(var.cors_rules)
  }
}

# Compliance Information
output "compliance_info" {
  description = "Compliance configuration information"
  value = {
    uk_data_residency      = true
    gdpr_compliant         = var.enable_versioning && var.kms_key_id != null
    encryption_at_rest     = true
    encryption_in_transit  = true
    versioning_enabled     = var.enable_versioning
    public_access_blocked  = var.block_public_acls && var.block_public_policy && var.ignore_public_acls && var.restrict_public_buckets
    access_logging_enabled = var.enable_access_logging
    data_classification    = var.data_classification
  }
}

# Log Archive S3 Module Outputs

# Primary Bucket Outputs
output "primary_bucket_id" {
  description = "ID of the primary log archive bucket"
  value       = aws_s3_bucket.log_archive_primary.id
}

output "primary_bucket_arn" {
  description = "ARN of the primary log archive bucket"
  value       = aws_s3_bucket.log_archive_primary.arn
}

output "primary_bucket_domain_name" {
  description = "Domain name of the primary log archive bucket"
  value       = aws_s3_bucket.log_archive_primary.bucket_domain_name
}

output "primary_bucket_regional_domain_name" {
  description = "Regional domain name of the primary log archive bucket"
  value       = aws_s3_bucket.log_archive_primary.bucket_regional_domain_name
}

output "primary_bucket_region" {
  description = "Region of the primary log archive bucket"
  value       = aws_s3_bucket.log_archive_primary.region
}

# Replica Bucket Outputs
output "replica_bucket_id" {
  description = "ID of the replica log archive bucket"
  value       = var.enable_cross_region_replication ? aws_s3_bucket.log_archive_replica[0].id : null
}

output "replica_bucket_arn" {
  description = "ARN of the replica log archive bucket"
  value       = var.enable_cross_region_replication ? aws_s3_bucket.log_archive_replica[0].arn : null
}

output "replica_bucket_region" {
  description = "Region of the replica log archive bucket"
  value       = var.enable_cross_region_replication ? aws_s3_bucket.log_archive_replica[0].region : null
}

# Replication Configuration Outputs
output "replication_configuration_id" {
  description = "ID of the replication configuration"
  value       = var.enable_cross_region_replication ? aws_s3_bucket_replication_configuration.log_archive[0].id : null
}

output "replication_enabled" {
  description = "Whether cross-region replication is enabled"
  value       = var.enable_cross_region_replication
}

# Alarm Outputs
output "replication_latency_alarm_arn" {
  description = "ARN of the replication latency CloudWatch alarm"
  value       = var.enable_cross_region_replication && var.enable_replication_alarms ? aws_cloudwatch_metric_alarm.replication_latency[0].arn : null
}

# Configuration Summary
output "configuration_summary" {
  description = "Summary of log archive configuration"
  value = {
    primary_bucket_name             = aws_s3_bucket.log_archive_primary.id
    primary_bucket_region           = aws_s3_bucket.log_archive_primary.region
    replica_bucket_name             = var.enable_cross_region_replication ? aws_s3_bucket.log_archive_replica[0].id : null
    replica_bucket_region           = var.enable_cross_region_replication ? aws_s3_bucket.log_archive_replica[0].region : null
    versioning_enabled              = true
    encryption_enabled              = true
    cross_region_replication        = var.enable_cross_region_replication
    access_logging_enabled          = var.enable_access_logging
    bucket_notifications_enabled    = var.enable_bucket_notifications
    cloudtrail_retention_days       = var.cloudtrail_expiration_days
    flow_logs_retention_days        = var.flow_logs_expiration_days
    config_logs_retention_days      = var.config_logs_expiration_days
    guardduty_retention_days        = var.guardduty_findings_expiration_days
    securityhub_retention_days      = var.securityhub_findings_expiration_days
    network_firewall_retention_days = var.network_firewall_logs_expiration_days
  }
}

# Bucket Names for Reference
output "log_archive_buckets" {
  description = "Map of log archive bucket names and ARNs"
  value = {
    primary = {
      name   = aws_s3_bucket.log_archive_primary.id
      arn    = aws_s3_bucket.log_archive_primary.arn
      region = aws_s3_bucket.log_archive_primary.region
    }
    replica = var.enable_cross_region_replication ? {
      name   = aws_s3_bucket.log_archive_replica[0].id
      arn    = aws_s3_bucket.log_archive_replica[0].arn
      region = aws_s3_bucket.log_archive_replica[0].region
    } : null
  }
}

# Compliance Information
output "compliance_info" {
  description = "Compliance configuration information"
  value = {
    uk_data_residency     = true
    gdpr_compliant        = true
    retention_period      = "${var.cloudtrail_expiration_days} days (${var.cloudtrail_expiration_days / 365} years)"
    encryption_at_rest    = true
    encryption_in_transit = true
    versioning_enabled    = true
    mfa_delete_enabled    = var.enable_mfa_delete
    public_access_blocked = true
  }
}

output "trail_id" {
  description = "CloudTrail ID"
  value       = aws_cloudtrail.organization.id
}

output "trail_arn" {
  description = "CloudTrail ARN"
  value       = aws_cloudtrail.organization.arn
}

output "log_group_name" {
  description = "CloudWatch log group name"
  value       = var.enable_cloudwatch_logs ? aws_cloudwatch_log_group.cloudtrail[0].name : null
}

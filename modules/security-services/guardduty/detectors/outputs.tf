# Outputs for GuardDuty Detectors Module

output "detector_id" {
  description = "The ID of the GuardDuty detector"
  value       = aws_guardduty_detector.uk_primary.id
}

output "detector_arn" {
  description = "The ARN of the GuardDuty detector"
  value       = aws_guardduty_detector.uk_primary.arn
}

output "detector_account_id" {
  description = "The AWS account ID of the GuardDuty detector"
  value       = aws_guardduty_detector.uk_primary.account_id
}

output "organization_admin_account_id" {
  description = "The organization admin account ID for GuardDuty"
  value       = var.is_organization_admin ? aws_guardduty_organization_admin_account.uk_admin[0].admin_account_id : null
}

output "publishing_destination_id" {
  description = "The ID of the GuardDuty publishing destination"
  value       = var.enable_publishing_destination ? aws_guardduty_publishing_destination.uk_findings[0].id : null
}

output "member_account_ids" {
  description = "List of member account IDs configured in GuardDuty"
  value       = [for member in aws_guardduty_member.uk_members : member.account_id]
}

output "high_severity_filter_arn" {
  description = "ARN of the high severity findings filter"
  value       = aws_guardduty_filter.uk_high_severity.arn
}

output "compliance_violations_filter_arn" {
  description = "ARN of the compliance violations filter"
  value       = aws_guardduty_filter.uk_compliance_violations.arn
}
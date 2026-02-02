output "security_hub_id" {
  description = "Security Hub account ID"
  value       = aws_securityhub_account.main.id
}

output "security_hub_arn" {
  description = "Security Hub account ARN"
  value       = aws_securityhub_account.main.arn
}

output "organization_admin_account_id" {
  description = "Security Hub organization admin account ID"
  value       = var.is_delegated_admin ? aws_securityhub_organization_admin_account.main[0].admin_account_id : null
}

output "finding_aggregator_arn" {
  description = "Security Hub finding aggregator ARN"
  value       = var.enable_finding_aggregation ? aws_securityhub_finding_aggregator.main[0].id : null
}

output "uk_compliance_master_insight_arn" {
  description = "compliance master insight ARN"
  value       = aws_securityhub_insight.uk_compliance_master.arn
}

output "uk_compliance_remediation_action_arn" {
  description = "compliance remediation action target ARN"
  value       = aws_securityhub_action_target.uk_compliance_remediation.arn
}

# Standards subscription outputs
output "aws_foundational_subscription_arn" {
  description = "AWS Foundational Security Best Practices subscription ARN"
  value       = module.compliance_standards.aws_foundational_subscription_arn
}

output "cis_benchmark_subscription_arn" {
  description = "CIS AWS Foundations Benchmark subscription ARN"
  value       = module.compliance_standards.cis_benchmark_subscription_arn
}

# Compliance framework insights
output "ncsc_insights" {
  description = "Security Standards compliance insights ARNs"
  value       = module.compliance_standards.ncsc_insights
}

output "cis_insights" {
  description = "CIS benchmark insights ARNs"
  value       = module.compliance_standards.cis_insights
}

output "aws_foundational_insights" {
  description = "AWS Foundational Security insights ARNs"
  value       = module.compliance_standards.aws_foundational_insights
}

# Action targets for remediation
output "remediation_actions" {
  description = "Security Hub action targets for automated remediation"
  value = {
    ncsc_remediation             = module.compliance_standards.ncsc_remediation_action_arn
    cis_remediation              = module.compliance_standards.cis_remediation_action_arn
    aws_foundational_remediation = module.compliance_standards.aws_foundational_remediation_action_arn
    uk_compliance_remediation    = aws_securityhub_action_target.uk_compliance_remediation.arn
  }
}

# Outputs for Security Hub Standards Module

# Security Standards Standards Outputs
output "ncsc_insights" {
  description = "Security Standards compliance insights ARNs"
  value = var.enable_ncsc_insights ? {
    compliance_violations           = aws_securityhub_insight.ncsc_compliance_violations.arn
    data_protection_violations      = aws_securityhub_insight.data_protection_violations.arn
    asset_protection_violations     = aws_securityhub_insight.asset_protection_violations.arn
    separation_violations           = aws_securityhub_insight.separation_violations.arn
    governance_violations           = aws_securityhub_insight.governance_violations.arn
    operational_security_violations = aws_securityhub_insight.operational_security_violations.arn
    personnel_security_violations   = aws_securityhub_insight.personnel_security_violations.arn
    uk_compliance_overview          = aws_securityhub_insight.uk_compliance_overview.arn
  } : {}
}

output "ncsc_remediation_action_arn" {
  description = "Security Standards remediation action target ARN"
  value       = var.enable_ncsc_insights ? aws_securityhub_action_target.ncsc_remediation.arn : null
}

# CIS Standards Outputs
output "cis_benchmark_subscription_arn" {
  description = "CIS AWS Foundations Benchmark subscription ARN"
  value       = var.enable_cis_standard ? aws_securityhub_standards_subscription.cis_benchmark[0].id : null
}

output "cis_insights" {
  description = "CIS benchmark insights ARNs"
  value = var.enable_cis_insights ? {
    critical_findings   = aws_securityhub_insight.cis_critical_findings.arn
    iam_findings        = aws_securityhub_insight.cis_iam_findings.arn
    logging_findings    = aws_securityhub_insight.cis_logging_findings.arn
    networking_findings = aws_securityhub_insight.cis_networking_findings.arn
    storage_findings    = aws_securityhub_insight.cis_storage_findings.arn
    compliance_summary  = aws_securityhub_insight.cis_compliance_summary.arn
    uk_cis_controls     = aws_securityhub_insight.uk_cis_controls.arn
  } : {}
}

output "cis_remediation_action_arn" {
  description = "CIS remediation action target ARN"
  value       = var.enable_cis_insights ? aws_securityhub_action_target.cis_remediation.arn : null
}

# AWS Foundational Standards Outputs
output "aws_foundational_subscription_arn" {
  description = "AWS Foundational Security Best Practices subscription ARN"
  value       = aws_securityhub_standards_subscription.aws_foundational.id
}

output "aws_foundational_insights" {
  description = "AWS Foundational Security insights ARNs"
  value = var.enable_aws_foundational_insights ? {
    critical_findings        = aws_securityhub_insight.aws_foundational_critical.arn
    high_findings            = aws_securityhub_insight.aws_foundational_high.arn
    ec2_findings             = aws_securityhub_insight.aws_foundational_ec2.arn
    s3_findings              = aws_securityhub_insight.aws_foundational_s3.arn
    rds_findings             = aws_securityhub_insight.aws_foundational_rds.arn
    lambda_findings          = aws_securityhub_insight.aws_foundational_lambda.arn
    iam_findings             = aws_securityhub_insight.aws_foundational_iam.arn
    compliance_summary       = aws_securityhub_insight.aws_foundational_summary.arn
    uk_foundational_controls = aws_securityhub_insight.uk_aws_foundational_controls.arn
  } : {}
}

output "aws_foundational_remediation_action_arn" {
  description = "AWS Foundational remediation action target ARN"
  value       = var.enable_aws_foundational_insights ? aws_securityhub_action_target.aws_foundational_remediation.arn : null
}
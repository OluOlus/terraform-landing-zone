# Outputs for GuardDuty Module

output "detector_id" {
  description = "The ID of the primary GuardDuty detector"
  value       = aws_guardduty_detector.main.id
}

output "detector_arn" {
  description = "The ARN of the primary GuardDuty detector"
  value       = aws_guardduty_detector.main.arn
}

output "detector_account_id" {
  description = "The AWS account ID of the GuardDuty detector"
  value       = aws_guardduty_detector.main.account_id
}

output "organization_admin_account_id" {
  description = "The organization admin account ID for GuardDuty"
  value       = var.is_delegated_admin ? aws_guardduty_organization_admin_account.main[0].admin_account_id : null
}

# Detectors module outputs
output "detectors_detector_id" {
  description = "The ID of the GuardDuty detector from detectors module"
  value       = module.detectors.detector_id
}

output "detectors_publishing_destination_id" {
  description = "The ID of the GuardDuty publishing destination"
  value       = module.detectors.publishing_destination_id
}

output "detectors_member_account_ids" {
  description = "List of member account IDs configured in GuardDuty"
  value       = module.detectors.member_account_ids
}

output "detectors_high_severity_filter_arn" {
  description = "ARN of the high severity findings filter"
  value       = module.detectors.high_severity_filter_arn
}

output "detectors_compliance_violations_filter_arn" {
  description = "ARN of the compliance violations filter"
  value       = module.detectors.compliance_violations_filter_arn
}

# UK Threat Intelligence outputs
output "uk_government_threats_id" {
  description = "ID of UK government threat intelligence set"
  value       = var.enable_uk_threat_intelligence ? aws_guardduty_threatintelset.uk_government_threats[0].id : null
}

output "ncsc_critical_infrastructure_threats_id" {
  description = "ID of Security Standards critical infrastructure threat intelligence set"
  value       = var.enable_ncsc_threat_intelligence ? aws_guardduty_threatintelset.ncsc_critical_infrastructure[0].id : null
}

output "uk_government_allowlist_id" {
  description = "ID of UK government IP allowlist"
  value       = var.enable_uk_government_allowlist ? aws_guardduty_ipset.uk_government_allowlist[0].id : null
}

output "uk_targeted_threats_blocklist_id" {
  description = "ID of UK-targeted threats blocklist"
  value       = var.enable_uk_targeted_threats_blocklist ? aws_guardduty_ipset.uk_targeted_threats[0].id : null
}

output "threat_intel_updater_function_arn" {
  description = "ARN of the threat intelligence updater Lambda function"
  value       = var.enable_automated_threat_intel_updates ? aws_lambda_function.threat_intel_updater[0].arn : null
}

# Cross-region outputs
output "alternate_detector_id" {
  description = "The ID of the alternate region GuardDuty detector"
  value       = var.enable_cross_region ? aws_guardduty_detector.uk_alternate[0].id : null
}

output "alternate_detector_arn" {
  description = "The ARN of the alternate region GuardDuty detector"
  value       = var.enable_cross_region ? aws_guardduty_detector.uk_alternate[0].arn : null
}

output "cross_region_findings_rule_arn" {
  description = "ARN of the cross-region findings EventBridge rule"
  value       = var.enable_cross_region && var.enable_cross_region_aggregation ? aws_cloudwatch_event_rule.cross_region_findings[0].arn : null
}

output "disaster_recovery_detector_id" {
  description = "The ID of the disaster recovery GuardDuty detector"
  value       = var.enable_disaster_recovery ? aws_guardduty_detector.uk_dr[0].id : null
}

# Summary outputs for monitoring and compliance
output "enabled_threat_intelligence_feeds" {
  description = "List of enabled threat intelligence feeds"
  value = compact([
    var.enable_uk_threat_intelligence ? "UK-Government" : "",
    var.enable_ncsc_threat_intelligence ? "Security Standards-Critical-Infrastructure" : "",
    var.enable_financial_threat_intelligence ? "UK-Financial-Services" : "",
    var.enable_healthcare_threat_intelligence ? "UK-Healthcare" : "",
    var.enable_brexit_threat_intelligence ? "Brexit-Related" : "",
    var.enable_cni_threat_intelligence ? "UK-CNI" : ""
  ])
}

output "enabled_ip_lists" {
  description = "List of enabled IP lists"
  value = compact([
    var.enable_uk_government_allowlist ? "UK-Government-Allowlist" : "",
    var.enable_uk_targeted_threats_blocklist ? "UK-Targeted-Threats-Blocklist" : ""
  ])
}

output "cross_region_enabled" {
  description = "Whether cross-region configuration is enabled"
  value       = var.enable_cross_region
}

output "uk_compliance_status" {
  description = "compliance configuration status"
  value = {
    uk_regions_only             = length(var.uk_regions) == 2
    threat_intelligence_enabled = var.enable_uk_threat_intelligence || var.enable_ncsc_threat_intelligence
    cross_region_enabled        = var.enable_cross_region
    malware_protection_enabled  = var.enable_malware_protection
    s3_logs_enabled             = var.enable_s3_logs
    kubernetes_logs_enabled     = var.enable_kubernetes_audit_logs
  }
}

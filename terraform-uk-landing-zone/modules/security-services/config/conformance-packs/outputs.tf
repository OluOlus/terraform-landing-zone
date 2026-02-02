# Conformance Packs Module Outputs
# Outputs for all compliance framework conformance packs

# Security Standards Conformance Pack Outputs
output "ncsc_pack_arn" {
  description = "Security Standards conformance pack ARN"
  value       = var.enable_ncsc_pack ? aws_config_conformance_pack.ncsc_principles[0].arn : null
}

output "ncsc_pack_name" {
  description = "Security Standards conformance pack name"
  value       = var.enable_ncsc_pack ? aws_config_conformance_pack.ncsc_principles[0].name : null
}

output "ncsc_config_rules" {
  description = "List of Security Standards Config rule names"
  value = compact([
    var.enable_ncsc_pack ? aws_config_config_rule.ncsc_uk_regions_only[0].name : "",
    var.enable_ncsc_pack ? aws_config_config_rule.ncsc_data_classification_tags[0].name : "",
    var.enable_ncsc_pack ? aws_config_config_rule.ncsc_encryption_in_transit[0].name : "",
    var.enable_ncsc_pack ? aws_config_config_rule.ncsc_multi_az_resilience[0].name : "",
    var.enable_ncsc_pack ? aws_config_config_rule.ncsc_operational_security[0].name : "",
    var.enable_ncsc_pack ? aws_config_config_rule.ncsc_personnel_security[0].name : "",
    var.enable_ncsc_pack ? aws_config_config_rule.ncsc_governance_framework[0].name : ""
  ])
}

# GDPR Conformance Pack Outputs
output "gdpr_pack_arn" {
  description = "GDPR conformance pack ARN"
  value       = var.enable_gdpr_pack ? aws_config_conformance_pack.uk_gdpr[0].arn : null
}

output "gdpr_pack_name" {
  description = "GDPR conformance pack name"
  value       = var.enable_gdpr_pack ? aws_config_conformance_pack.uk_gdpr[0].name : null
}

output "gdpr_config_rules" {
  description = "List of GDPR Config rule names"
  value = compact([
    var.enable_gdpr_pack ? aws_config_config_rule.gdpr_data_protection_by_design[0].name : "",
    var.enable_gdpr_pack ? aws_config_config_rule.gdpr_processing_records[0].name : "",
    var.enable_gdpr_pack ? aws_config_config_rule.gdpr_security_of_processing[0].name : "",
    var.enable_gdpr_pack ? aws_config_config_rule.gdpr_breach_notification[0].name : "",
    var.enable_gdpr_pack ? aws_config_config_rule.gdpr_data_protection_impact_assessment[0].name : "",
    var.enable_gdpr_pack ? aws_config_config_rule.gdpr_right_to_be_forgotten[0].name : "",
    var.enable_gdpr_pack ? aws_config_config_rule.gdpr_data_portability[0].name : "",
    var.enable_gdpr_pack ? aws_config_config_rule.gdpr_lawfulness_of_processing[0].name : "",
    var.enable_gdpr_pack ? aws_config_config_rule.gdpr_data_minimization[0].name : "",
    var.enable_gdpr_pack ? aws_config_config_rule.gdpr_cross_border_transfers[0].name : ""
  ])
}

# Security Essentials Conformance Pack Outputs
output "cyber_essentials_pack_arn" {
  description = "Security Essentials conformance pack ARN"
  value       = var.enable_cyber_essentials_pack ? aws_config_conformance_pack.cyber_essentials[0].arn : null
}

output "cyber_essentials_pack_name" {
  description = "Security Essentials conformance pack name"
  value       = var.enable_cyber_essentials_pack ? aws_config_conformance_pack.cyber_essentials[0].name : null
}

output "cyber_essentials_config_rules" {
  description = "List of Security Essentials Config rule names"
  value = compact([
    var.enable_cyber_essentials_pack ? aws_config_config_rule.ce_boundary_firewalls[0].name : "",
    var.enable_cyber_essentials_pack ? aws_config_config_rule.ce_network_acls[0].name : "",
    var.enable_cyber_essentials_pack ? aws_config_config_rule.ce_secure_configuration_ssm[0].name : "",
    var.enable_cyber_essentials_pack ? aws_config_config_rule.ce_no_default_passwords[0].name : "",
    var.enable_cyber_essentials_pack ? aws_config_config_rule.ce_access_control_mfa[0].name : "",
    var.enable_cyber_essentials_pack ? aws_config_config_rule.ce_privileged_access_management[0].name : "",
    var.enable_cyber_essentials_pack ? aws_config_config_rule.ce_user_account_management[0].name : "",
    var.enable_cyber_essentials_pack ? aws_config_config_rule.ce_malware_protection_guardduty[0].name : "",
    var.enable_cyber_essentials_pack ? aws_config_config_rule.ce_endpoint_protection_monitoring[0].name : "",
    var.enable_cyber_essentials_pack ? aws_config_config_rule.ce_patch_management_compliance[0].name : "",
    var.enable_cyber_essentials_pack ? aws_config_config_rule.ce_software_update_management[0].name : "",
    var.enable_cyber_essentials_pack ? aws_config_config_rule.ce_data_encryption_at_rest[0].name : "",
    var.enable_cyber_essentials_pack ? aws_config_config_rule.ce_audit_logging[0].name : "",
    var.enable_cyber_essentials_pack ? aws_config_config_rule.ce_asset_management_tagging[0].name : ""
  ])
}

# Summary Outputs
output "total_conformance_packs" {
  description = "Total number of conformance packs deployed"
  value = (
    (var.enable_ncsc_pack ? 1 : 0) +
    (var.enable_gdpr_pack ? 1 : 0) +
    (var.enable_cyber_essentials_pack ? 1 : 0)
  )
}

output "total_config_rules" {
  description = "Total number of custom Config rules deployed"
  value = (
    length(local.ncsc_rules) +
    length(local.gdpr_rules) +
    length(local.ce_rules)
  )
}

# Local values for rule counting
locals {
  ncsc_rules = var.enable_ncsc_pack ? [
    "ncsc_uk_regions_only",
    "ncsc_data_classification_tags",
    "ncsc_encryption_in_transit",
    "ncsc_multi_az_resilience",
    "ncsc_operational_security",
    "ncsc_personnel_security",
    "ncsc_governance_framework"
  ] : []

  gdpr_rules = var.enable_gdpr_pack ? [
    "gdpr_data_protection_by_design",
    "gdpr_processing_records",
    "gdpr_security_of_processing",
    "gdpr_breach_notification",
    "gdpr_data_protection_impact_assessment",
    "gdpr_right_to_be_forgotten",
    "gdpr_data_portability",
    "gdpr_lawfulness_of_processing",
    "gdpr_data_minimization",
    "gdpr_cross_border_transfers"
  ] : []

  ce_rules = var.enable_cyber_essentials_pack ? [
    "ce_boundary_firewalls",
    "ce_network_acls",
    "ce_secure_configuration_ssm",
    "ce_no_default_passwords",
    "ce_access_control_mfa",
    "ce_privileged_access_management",
    "ce_user_account_management",
    "ce_malware_protection_guardduty",
    "ce_endpoint_protection_monitoring",
    "ce_patch_management_compliance",
    "ce_software_update_management",
    "ce_data_encryption_at_rest",
    "ce_audit_logging",
    "ce_asset_management_tagging"
  ] : []
}
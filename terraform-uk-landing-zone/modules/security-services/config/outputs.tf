# AWS Config Module Outputs
# Outputs for compliance monitoring resources

# Config Recorder Outputs
output "config_recorder_name" {
  description = "Name of the Config recorder"
  value       = var.enable_config_recorder ? aws_config_configuration_recorder.main[0].name : null
}

output "config_recorder_arn" {
  description = "ARN of the Config recorder"
  value       = var.enable_config_recorder ? aws_config_configuration_recorder.main[0].name : null
}

# Delivery Channel Outputs
output "delivery_channel_name" {
  description = "Name of the Config delivery channel"
  value       = var.enable_config_recorder ? aws_config_delivery_channel.main[0].name : null
}

# Organization Aggregator Outputs
output "aggregator_arn" {
  description = "Config aggregator ARN"
  value       = var.is_delegated_admin ? aws_config_configuration_aggregator.organization[0].arn : null
}

output "aggregator_name" {
  description = "Config aggregator name"
  value       = var.is_delegated_admin ? aws_config_configuration_aggregator.organization[0].name : null
}

# Security Standards Conformance Pack Outputs
output "ncsc_pack_arn" {
  description = "Security Standards conformance pack ARN"
  value       = module.ncsc_conformance_pack.ncsc_pack_arn
}

output "ncsc_pack_name" {
  description = "Security Standards conformance pack name"
  value       = var.enable_ncsc_pack ? "ncsc-cloud-security-principles" : null
}

# GDPR Conformance Pack Outputs
output "gdpr_pack_arn" {
  description = "GDPR conformance pack ARN"
  value       = module.ncsc_conformance_pack.gdpr_pack_arn
}

output "gdpr_pack_name" {
  description = "GDPR conformance pack name"
  value       = var.enable_gdpr_pack ? "uk-gdpr-compliance" : null
}

# Security Essentials Conformance Pack Outputs
output "cyber_essentials_pack_arn" {
  description = "Security Essentials conformance pack ARN"
  value       = module.ncsc_conformance_pack.cyber_essentials_pack_arn
}

output "cyber_essentials_pack_name" {
  description = "Security Essentials conformance pack name"
  value       = var.enable_cyber_essentials_pack ? "cyber-essentials-compliance" : null
}

# Custom Config Rules Outputs
output "uk_data_residency_rule_arn" {
  description = "UK data residency rule ARN"
  value       = var.enable_uk_data_residency_rule ? aws_config_config_rule.uk_data_residency[0].arn : null
}

output "uk_mandatory_tagging_rule_arn" {
  description = "UK mandatory tagging rule ARN"
  value       = var.enable_uk_mandatory_tagging_rule ? aws_config_config_rule.uk_mandatory_tagging[0].arn : null
}

# Compliance Summary Outputs
output "enabled_compliance_frameworks" {
  description = "List of enabled compliance frameworks"
  value = compact([
    var.enable_ncsc_pack ? "Security Standards" : "",
    var.enable_gdpr_pack ? "UK-GDPR" : "",
    var.enable_cyber_essentials_pack ? "Cyber-Essentials" : ""
  ])
}

output "config_rules_count" {
  description = "Total number of Config rules deployed"
  value = (
    (var.enable_uk_data_residency_rule ? 1 : 0) +
    (var.enable_uk_mandatory_tagging_rule ? 1 : 0)
  )
}

output "conformance_packs_count" {
  description = "Total number of conformance packs deployed"
  value = (
    (var.enable_ncsc_pack ? 1 : 0) +
    (var.enable_gdpr_pack ? 1 : 0) +
    (var.enable_cyber_essentials_pack ? 1 : 0)
  )
}

# Security Essentials Compliance Conformance Pack
# This module implements AWS Config conformance pack for Security Essentials compliance
# Requirements: 7.5, 2.7

# Security Essentials Compliance Conformance Pack
resource "aws_config_conformance_pack" "cyber_essentials" {
  count = var.enable_cyber_essentials_pack ? 1 : 0

  name = "cyber-essentials-compliance"

  # Input parameters for Security Essentials-specific configurations
  input_parameter {
    parameter_name  = "FirewallTimeoutSeconds"
    parameter_value = var.ce_firewall_timeout_seconds
  }

  input_parameter {
    parameter_name  = "PatchComplianceTimeoutDays"
    parameter_value = var.ce_patch_compliance_timeout_days
  }

  input_parameter {
    parameter_name  = "PasswordComplexityMinLength"
    parameter_value = var.ce_password_min_length
  }

  template_body = file("${path.module}/cyber-essentials-pack.yaml")

  depends_on = [var.config_recorder_dependency]
}

# Security Essentials Control 1: Boundary Firewalls and Internet Gateways
resource "aws_config_config_rule" "ce_boundary_firewalls" {
  count = var.enable_cyber_essentials_pack ? 1 : 0

  name = "ce-boundary-firewalls-security-groups"

  source {
    owner             = "AWS"
    source_identifier = "SECURITY_GROUPS_RESTRICTED_INCOMING_TRAFFIC"
  }

  input_parameters = jsonencode({
    blockedPort1 = "22"
    blockedPort2 = "3389"
    blockedPort3 = "21"
    blockedPort4 = "23"
    blockedPort5 = "135"
  })

  scope {
    compliance_resource_types = [
      "AWS::EC2::SecurityGroup"
    ]
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "ce-boundary-firewalls-security-groups"
    ComplianceFramework = "Cyber-Essentials"
    Control             = "Control 1"
    ControlName         = "Boundary Firewalls"
  })
}

# Security Essentials Control 1: Network Access Control Lists
resource "aws_config_config_rule" "ce_network_acls" {
  count = var.enable_cyber_essentials_pack ? 1 : 0

  name = "ce-network-acls-no-unrestricted-access"

  source {
    owner             = "AWS"
    source_identifier = "NACL_NO_UNRESTRICTED_SOURCE_IN_SSH"
  }

  scope {
    compliance_resource_types = [
      "AWS::EC2::NetworkAcl"
    ]
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "ce-network-acls-no-unrestricted-access"
    ComplianceFramework = "Cyber-Essentials"
    Control             = "Control 1"
    ControlName         = "Network Access Control"
  })
}

# Security Essentials Control 2: Secure Configuration
resource "aws_config_config_rule" "ce_secure_configuration_ssm" {
  count = var.enable_cyber_essentials_pack ? 1 : 0

  name = "ce-secure-configuration-ssm-managed"

  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_MANAGED_BY_SSM"
  }

  scope {
    compliance_resource_types = [
      "AWS::EC2::Instance"
    ]
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "ce-secure-configuration-ssm-managed"
    ComplianceFramework = "Cyber-Essentials"
    Control             = "Control 2"
    ControlName         = "Secure Configuration"
  })
}

# Security Essentials Control 2: Default Passwords and Configuration
resource "aws_config_config_rule" "ce_no_default_passwords" {
  count = var.enable_cyber_essentials_pack ? 1 : 0

  name = "ce-no-default-passwords-policy"

  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }

  input_parameters = jsonencode({
    RequireUppercaseCharacters = "true"
    RequireLowercaseCharacters = "true"
    RequireNumbers             = "true"
    RequireSymbols             = "true"
    MinimumPasswordLength      = var.ce_password_min_length
    PasswordReusePrevention    = "24"
    MaxPasswordAge             = "90"
  })

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "ce-no-default-passwords-policy"
    ComplianceFramework = "Cyber-Essentials"
    Control             = "Control 2"
    ControlName         = "Secure Configuration"
  })
}

# Security Essentials Control 3: Access Control
resource "aws_config_config_rule" "ce_access_control_mfa" {
  count = var.enable_cyber_essentials_pack ? 1 : 0

  name = "ce-access-control-mfa-enabled"

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_MFA_ENABLED"
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "ce-access-control-mfa-enabled"
    ComplianceFramework = "Cyber-Essentials"
    Control             = "Control 3"
    ControlName         = "Access Control"
  })
}

# Security Essentials Control 3: Privileged Access Management
resource "aws_config_config_rule" "ce_privileged_access_management" {
  count = var.enable_cyber_essentials_pack ? 1 : 0

  name = "ce-privileged-access-no-admin-policies"

  source {
    owner             = "AWS"
    source_identifier = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"
  }

  scope {
    compliance_resource_types = [
      "AWS::IAM::Policy"
    ]
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "ce-privileged-access-no-admin-policies"
    ComplianceFramework = "Cyber-Essentials"
    Control             = "Control 3"
    ControlName         = "Access Control"
  })
}

# Security Essentials Control 3: User Account Management
resource "aws_config_config_rule" "ce_user_account_management" {
  count = var.enable_cyber_essentials_pack ? 1 : 0

  name = "ce-user-account-unused-credentials"

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_UNUSED_CREDENTIALS_CHECK"
  }

  input_parameters = jsonencode({
    maxCredentialUsageAge = "90"
  })

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "ce-user-account-unused-credentials"
    ComplianceFramework = "Cyber-Essentials"
    Control             = "Control 3"
    ControlName         = "Access Control"
  })
}

# Security Essentials Control 4: Malware Protection
resource "aws_config_config_rule" "ce_malware_protection_guardduty" {
  count = var.enable_cyber_essentials_pack ? 1 : 0

  name = "ce-malware-protection-guardduty"

  source {
    owner             = "AWS"
    source_identifier = "GUARDDUTY_ENABLED_CENTRALIZED"
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "ce-malware-protection-guardduty"
    ComplianceFramework = "Cyber-Essentials"
    Control             = "Control 4"
    ControlName         = "Malware Protection"
  })
}

# Security Essentials Control 4: Endpoint Protection
resource "aws_config_config_rule" "ce_endpoint_protection_monitoring" {
  count = var.enable_cyber_essentials_pack ? 1 : 0

  name = "ce-endpoint-protection-detailed-monitoring"

  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_DETAILED_MONITORING_ENABLED"
  }

  scope {
    compliance_resource_types = [
      "AWS::EC2::Instance"
    ]
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "ce-endpoint-protection-detailed-monitoring"
    ComplianceFramework = "Cyber-Essentials"
    Control             = "Control 4"
    ControlName         = "Malware Protection"
  })
}

# Security Essentials Control 5: Patch Management
resource "aws_config_config_rule" "ce_patch_management_compliance" {
  count = var.enable_cyber_essentials_pack ? 1 : 0

  name = "ce-patch-management-compliance"

  source {
    owner             = "AWS"
    source_identifier = "EC2_MANAGEDINSTANCE_PATCH_COMPLIANCE_STATUS_CHECK"
  }

  scope {
    compliance_resource_types = [
      "AWS::SSM::PatchCompliance"
    ]
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "ce-patch-management-compliance"
    ComplianceFramework = "Cyber-Essentials"
    Control             = "Control 5"
    ControlName         = "Patch Management"
  })
}

# Security Essentials Control 5: Software Update Management
resource "aws_config_config_rule" "ce_software_update_management" {
  count = var.enable_cyber_essentials_pack ? 1 : 0

  name = "ce-software-update-association-compliance"

  source {
    owner             = "AWS"
    source_identifier = "EC2_MANAGEDINSTANCE_ASSOCIATION_COMPLIANCE_STATUS_CHECK"
  }

  scope {
    compliance_resource_types = [
      "AWS::SSM::AssociationCompliance"
    ]
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "ce-software-update-association-compliance"
    ComplianceFramework = "Cyber-Essentials"
    Control             = "Control 5"
    ControlName         = "Patch Management"
  })
}

# Additional Security Essentials Security Controls
resource "aws_config_config_rule" "ce_data_encryption_at_rest" {
  count = var.enable_cyber_essentials_pack ? 1 : 0

  name = "ce-data-encryption-at-rest"

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  input_parameters = jsonencode({
    kmsKeyIds = var.ce_encryption_key_ids
  })

  scope {
    compliance_resource_types = [
      "AWS::EC2::Volume"
    ]
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "ce-data-encryption-at-rest"
    ComplianceFramework = "Cyber-Essentials"
    Control             = "Additional Security"
    ControlName         = "Data Protection"
  })
}

# Security Essentials Audit Logging
resource "aws_config_config_rule" "ce_audit_logging" {
  count = var.enable_cyber_essentials_pack ? 1 : 0

  name = "ce-audit-logging-cloudtrail"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "ce-audit-logging-cloudtrail"
    ComplianceFramework = "Cyber-Essentials"
    Control             = "Additional Security"
    ControlName         = "Audit Logging"
  })
}

# Security Essentials Asset Management
resource "aws_config_config_rule" "ce_asset_management_tagging" {
  count = var.enable_cyber_essentials_pack ? 1 : 0

  name = "ce-asset-management-required-tags"

  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }

  input_parameters = jsonencode({
    tag1Key   = "Environment"
    tag2Key   = "Owner"
    tag3Key   = "CriticalityLevel"
    tag3Value = "low,medium,high,critical"
    tag4Key   = "PatchGroup"
    tag5Key   = "BackupRequired"
    tag5Value = "yes,no"
  })

  scope {
    compliance_resource_types = [
      "AWS::EC2::Instance",
      "AWS::S3::Bucket",
      "AWS::RDS::DBInstance",
      "AWS::ElasticLoadBalancing::LoadBalancer"
    ]
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "ce-asset-management-required-tags"
    ComplianceFramework = "Cyber-Essentials"
    Control             = "Additional Security"
    ControlName         = "Asset Management"
  })
}
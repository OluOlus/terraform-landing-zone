# Security Standards Cloud Security Principles Conformance Pack
# This module implements AWS Config conformance pack for Security Standards Cloud Security Principles
# Requirements: 7.5, 2.7

# Security Standards Cloud Security Principles Conformance Pack
resource "aws_config_conformance_pack" "ncsc_principles" {
  count = var.enable_ncsc_pack ? 1 : 0

  name = "ncsc-cloud-security-principles"

  # Input parameters for Security Standards-specific configurations
  input_parameter {
    parameter_name  = "AccessKeysRotatedParameterMaxAccessKeyAge"
    parameter_value = var.ncsc_access_key_max_age
  }

  input_parameter {
    parameter_name  = "EncryptedVolumesParameterKmsKeyId"
    parameter_value = var.ncsc_kms_key_id
  }

  input_parameter {
    parameter_name  = "S3BucketPublicAccessProhibitedParameterIgnorePublicAcls"
    parameter_value = "true"
  }

  input_parameter {
    parameter_name  = "RootUserMfaEnabledParameterMaxCredentialUsageAge"
    parameter_value = var.ncsc_root_credential_max_age
  }

  template_body = file("${path.module}/ncsc-pack.yaml")

  depends_on = [var.config_recorder_dependency]
}

# Custom Config rules for Security Standards-specific requirements
resource "aws_config_config_rule" "ncsc_uk_regions_only" {
  count = var.enable_ncsc_pack ? 1 : 0

  name = "ncsc-uk-regions-only"

  source {
    owner             = "AWS"
    source_identifier = "APPROVED_AMIS_BY_ID"
  }

  input_parameters = jsonencode({
    amiIds = join(",", var.ncsc_approved_ami_ids)
  })

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "ncsc-uk-regions-only"
    ComplianceFramework = "Security Standards"
    Principle           = "Data Residency"
  })
}

# Security Standards Data Classification Tagging Rule
resource "aws_config_config_rule" "ncsc_data_classification_tags" {
  count = var.enable_ncsc_pack ? 1 : 0

  name = "ncsc-data-classification-tags"

  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }

  input_parameters = jsonencode({
    tag1Key   = "DataClassification"
    tag1Value = "public,internal,confidential,restricted"
    tag2Key   = "SecurityClassification"
    tag2Value = "official,secret,top-secret"
    tag3Key   = "ComplianceFramework"
    tag4Key   = "DataResidency"
    tag4Value = "UK"
  })

  scope {
    compliance_resource_types = [
      "AWS::S3::Bucket",
      "AWS::RDS::DBInstance",
      "AWS::EC2::Instance",
      "AWS::DynamoDB::Table",
      "AWS::EFS::FileSystem"
    ]
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "ncsc-data-classification-tags"
    ComplianceFramework = "Security Standards"
    Principle           = "Data Classification"
  })
}

# Security Standards Encryption in Transit Rule
resource "aws_config_config_rule" "ncsc_encryption_in_transit" {
  count = var.enable_ncsc_pack ? 1 : 0

  name = "ncsc-encryption-in-transit"

  source {
    owner             = "AWS"
    source_identifier = "ELB_TLS_HTTPS_LISTENERS_ONLY"
  }

  scope {
    compliance_resource_types = [
      "AWS::ElasticLoadBalancing::LoadBalancer",
      "AWS::ElasticLoadBalancingV2::LoadBalancer"
    ]
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "ncsc-encryption-in-transit"
    ComplianceFramework = "Security Standards"
    Principle           = "Data Protection in Transit"
  })
}

# Security Standards Multi-AZ Resilience Rule
resource "aws_config_config_rule" "ncsc_multi_az_resilience" {
  count = var.enable_ncsc_pack ? 1 : 0

  name = "ncsc-multi-az-resilience"

  source {
    owner             = "AWS"
    source_identifier = "RDS_MULTI_AZ_SUPPORT"
  }

  scope {
    compliance_resource_types = [
      "AWS::RDS::DBInstance"
    ]
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "ncsc-multi-az-resilience"
    ComplianceFramework = "Security Standards"
    Principle           = "Asset Protection and Resilience"
  })
}

# Security Standards Operational Security Monitoring Rule
resource "aws_config_config_rule" "ncsc_operational_security" {
  count = var.enable_ncsc_pack ? 1 : 0

  name = "ncsc-operational-security-monitoring"

  source {
    owner             = "AWS"
    source_identifier = "CLOUDWATCH_LOG_GROUP_ENCRYPTED"
  }

  scope {
    compliance_resource_types = [
      "AWS::Logs::LogGroup"
    ]
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "ncsc-operational-security-monitoring"
    ComplianceFramework = "Security Standards"
    Principle           = "Operational Security"
  })
}

# Security Standards Personnel Security Rule
resource "aws_config_config_rule" "ncsc_personnel_security" {
  count = var.enable_ncsc_pack ? 1 : 0

  name = "ncsc-personnel-security-mfa"

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_MFA_ENABLED"
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "ncsc-personnel-security-mfa"
    ComplianceFramework = "Security Standards"
    Principle           = "Personnel Security"
  })
}

# Security Standards Governance Framework Rule
resource "aws_config_config_rule" "ncsc_governance_framework" {
  count = var.enable_ncsc_pack ? 1 : 0

  name = "ncsc-governance-framework"

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
    Name                = "ncsc-governance-framework"
    ComplianceFramework = "Security Standards"
    Principle           = "Governance Framework"
  })
}
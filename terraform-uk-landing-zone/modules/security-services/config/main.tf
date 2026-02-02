# AWS Config Module - UK Compliance Monitoring
# This module provides comprehensive compliance monitoring for the UK AWS Secure Landing Zone
# with support for Security Standards Cloud Security Principles, GDPR, and Security Essentials frameworks

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Enable AWS Config service
resource "aws_config_configuration_recorder" "main" {
  count = var.enable_config_recorder ? 1 : 0

  name     = var.config_recorder_name
  role_arn = var.config_service_role_arn

  recording_group {
    all_supported                 = var.record_all_supported
    include_global_resource_types = var.include_global_resources

    # region-specific resource types for compliance monitoring
    resource_types = var.record_all_supported ? [] : [
      "AWS::EC2::Instance",
      "AWS::EC2::Volume",
      "AWS::EC2::SecurityGroup",
      "AWS::EC2::VPC",
      "AWS::S3::Bucket",
      "AWS::RDS::DBInstance",
      "AWS::IAM::User",
      "AWS::IAM::Role",
      "AWS::IAM::Policy",
      "AWS::KMS::Key",
      "AWS::CloudTrail::Trail",
      "AWS::Logs::LogGroup"
    ]
  }

  recording_mode {
    recording_frequency = var.recording_frequency
    recording_mode_override {
      description         = "Override for global resources"
      recording_frequency = "DAILY"
      resource_types      = ["AWS::IAM::User", "AWS::IAM::Role", "AWS::IAM::Policy"]
    }
  }
}

# Config delivery channel
resource "aws_config_delivery_channel" "main" {
  count = var.enable_config_recorder ? 1 : 0

  name           = var.delivery_channel_name
  s3_bucket_name = var.config_s3_bucket_name
  s3_key_prefix  = var.config_s3_key_prefix

  snapshot_delivery_properties {
    delivery_frequency = var.snapshot_delivery_frequency
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Organization-wide Config aggregator (for Security Tooling Account)
resource "aws_config_configuration_aggregator" "organization" {
  count = var.is_delegated_admin ? 1 : 0
  name  = var.aggregator_name

  organization_aggregation_source {
    all_regions = true
    role_arn    = var.organization_role_arn
  }

  depends_on = [aws_config_configuration_recorder.main]

  tags = merge(var.common_tags, {
    Name               = var.aggregator_name
    Purpose            = "Organization-wide Config Aggregation"
    DataClassification = "confidential"
  })
}

# Include conformance packs modules
module "ncsc_conformance_pack" {
  source = "./conformance-packs"

  # Security Standards-specific variables
  enable_ncsc_pack             = var.enable_ncsc_pack
  ncsc_access_key_max_age      = var.ncsc_access_key_max_age
  ncsc_kms_key_id              = var.ncsc_kms_key_id
  ncsc_root_credential_max_age = var.ncsc_root_credential_max_age
  ncsc_approved_ami_ids        = var.ncsc_approved_ami_ids

  # GDPR-specific variables
  enable_gdpr_pack               = var.enable_gdpr_pack
  gdpr_data_retention_days       = var.gdpr_data_retention_days
  gdpr_key_rotation_days         = var.gdpr_key_rotation_days
  gdpr_access_log_retention_days = var.gdpr_access_log_retention_days
  gdpr_encryption_key_ids        = var.gdpr_encryption_key_ids

  # Security Essentials-specific variables
  enable_cyber_essentials_pack     = var.enable_cyber_essentials_pack
  ce_firewall_timeout_seconds      = var.ce_firewall_timeout_seconds
  ce_patch_compliance_timeout_days = var.ce_patch_compliance_timeout_days
  ce_password_min_length           = var.ce_password_min_length
  ce_encryption_key_ids            = var.ce_encryption_key_ids

  # Common variables
  config_recorder_dependency = var.enable_config_recorder ? aws_config_configuration_recorder.main[0].name : null
  common_tags                = var.common_tags
}

# Custom Config rules for region-specific requirements
resource "aws_config_config_rule" "uk_data_residency" {
  count = var.enable_uk_data_residency_rule ? 1 : 0

  name = "uk-data-residency-enforcement"

  source {
    owner             = "AWS"
    source_identifier = "APPROVED_AMIS_BY_ID"
  }

  input_parameters = jsonencode({
    amiIds = join(",", var.uk_approved_ami_ids)
  })

  scope {
    compliance_resource_types = [
      "AWS::EC2::Instance"
    ]
  }

  depends_on = [aws_config_configuration_recorder.main]

  tags = merge(var.common_tags, {
    Name                = "uk-data-residency-enforcement"
    ComplianceFramework = "UK-Data-Residency"
    Purpose             = "Enforce UK AMI usage"
  })
}

# UK mandatory tagging rule
resource "aws_config_config_rule" "uk_mandatory_tagging" {
  count = var.enable_uk_mandatory_tagging_rule ? 1 : 0

  name = "uk-mandatory-tagging-compliance"

  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }

  input_parameters = jsonencode({
    tag1Key   = "DataClassification"
    tag1Value = "public,internal,confidential,restricted"
    tag2Key   = "Environment"
    tag2Value = "production,non-production,sandbox"
    tag3Key   = "CostCenter"
    tag4Key   = "Owner"
    tag5Key   = "Project"
  })

  scope {
    compliance_resource_types = var.uk_mandatory_tagging_resource_types
  }

  depends_on = [aws_config_configuration_recorder.main]

  tags = merge(var.common_tags, {
    Name                = "uk-mandatory-tagging-compliance"
    ComplianceFramework = "UK-Tagging-Strategy"
    Purpose             = "Enforce mandatory UK tags"
  })
}

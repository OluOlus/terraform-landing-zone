# GDPR Compliance Conformance Pack
# This module implements AWS Config conformance pack for GDPR compliance
# Requirements: 7.5, 2.7

# GDPR Compliance Conformance Pack
resource "aws_config_conformance_pack" "uk_gdpr" {
  count = var.enable_gdpr_pack ? 1 : 0

  name = "uk-gdpr-compliance"

  # Input parameters for GDPR-specific configurations
  input_parameter {
    parameter_name  = "DataRetentionPeriodDays"
    parameter_value = var.gdpr_data_retention_days
  }

  input_parameter {
    parameter_name  = "EncryptionKeyRotationDays"
    parameter_value = var.gdpr_key_rotation_days
  }

  input_parameter {
    parameter_name  = "AccessLogRetentionDays"
    parameter_value = var.gdpr_access_log_retention_days
  }

  template_body = file("${path.module}/uk-gdpr-pack.yaml")

  depends_on = [var.config_recorder_dependency]
}

# GDPR Article 25: Data Protection by Design and by Default
resource "aws_config_config_rule" "gdpr_data_protection_by_design" {
  count = var.enable_gdpr_pack ? 1 : 0

  name = "gdpr-data-protection-by-design"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_DEFAULT_LOCK_ENABLED"
  }

  scope {
    compliance_resource_types = [
      "AWS::S3::Bucket"
    ]
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "gdpr-data-protection-by-design"
    ComplianceFramework = "UK-GDPR"
    Article             = "Article 25"
    Principle           = "Data Protection by Design"
  })
}

# GDPR Article 30: Records of Processing Activities
resource "aws_config_config_rule" "gdpr_processing_records" {
  count = var.enable_gdpr_pack ? 1 : 0

  name = "gdpr-processing-activity-records"

  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }

  input_parameters = jsonencode({
    tag1Key   = "DataSubjectCategory"
    tag1Value = "customer,employee,supplier,visitor"
    tag2Key   = "ProcessingPurpose"
    tag2Value = "service-delivery,hr-management,financial-management,marketing"
    tag3Key   = "LegalBasis"
    tag3Value = "consent,contract,legal-obligation,vital-interests,public-task,legitimate-interests"
    tag4Key   = "DataController"
    tag5Key   = "RetentionPeriod"
    tag6Key   = "DataCategories"
    tag6Value = "personal,sensitive,financial,health"
  })

  scope {
    compliance_resource_types = [
      "AWS::S3::Bucket",
      "AWS::RDS::DBInstance",
      "AWS::DynamoDB::Table",
      "AWS::EFS::FileSystem"
    ]
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "gdpr-processing-activity-records"
    ComplianceFramework = "UK-GDPR"
    Article             = "Article 30"
    Principle           = "Records of Processing"
  })
}

# GDPR Article 32: Security of Processing
resource "aws_config_config_rule" "gdpr_security_of_processing" {
  count = var.enable_gdpr_pack ? 1 : 0

  name = "gdpr-security-of-processing"

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  input_parameters = jsonencode({
    kmsKeyIds = var.gdpr_encryption_key_ids
  })

  scope {
    compliance_resource_types = [
      "AWS::EC2::Volume"
    ]
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "gdpr-security-of-processing"
    ComplianceFramework = "UK-GDPR"
    Article             = "Article 32"
    Principle           = "Security of Processing"
  })
}

# GDPR Article 33: Notification of Personal Data Breach
resource "aws_config_config_rule" "gdpr_breach_notification" {
  count = var.enable_gdpr_pack ? 1 : 0

  name = "gdpr-breach-notification-monitoring"

  source {
    owner             = "AWS"
    source_identifier = "GUARDDUTY_ENABLED_CENTRALIZED"
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "gdpr-breach-notification-monitoring"
    ComplianceFramework = "UK-GDPR"
    Article             = "Article 33"
    Principle           = "Breach Notification"
  })
}

# GDPR Article 35: Data Protection Impact Assessment
resource "aws_config_config_rule" "gdpr_data_protection_impact_assessment" {
  count = var.enable_gdpr_pack ? 1 : 0

  name = "gdpr-dpia-high-risk-processing"

  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }

  input_parameters = jsonencode({
    tag1Key   = "DPIARequired"
    tag1Value = "yes,no"
    tag2Key   = "DPIAStatus"
    tag2Value = "completed,in-progress,not-required"
    tag3Key   = "RiskLevel"
    tag3Value = "low,medium,high"
    tag4Key   = "DataMinimization"
    tag4Value = "implemented,not-applicable"
  })

  scope {
    compliance_resource_types = [
      "AWS::S3::Bucket",
      "AWS::RDS::DBInstance",
      "AWS::DynamoDB::Table"
    ]
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "gdpr-dpia-high-risk-processing"
    ComplianceFramework = "UK-GDPR"
    Article             = "Article 35"
    Principle           = "Data Protection Impact Assessment"
  })
}

# GDPR Right to be Forgotten (Article 17)
resource "aws_config_config_rule" "gdpr_right_to_be_forgotten" {
  count = var.enable_gdpr_pack ? 1 : 0

  name = "gdpr-right-to-erasure"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LIFECYCLE_CONFIGURATION_RULE"
  }

  scope {
    compliance_resource_types = [
      "AWS::S3::Bucket"
    ]
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "gdpr-right-to-erasure"
    ComplianceFramework = "UK-GDPR"
    Article             = "Article 17"
    Principle           = "Right to Erasure"
  })
}

# GDPR Data Portability (Article 20)
resource "aws_config_config_rule" "gdpr_data_portability" {
  count = var.enable_gdpr_pack ? 1 : 0

  name = "gdpr-data-portability"

  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }

  input_parameters = jsonencode({
    tag1Key   = "DataPortabilityEnabled"
    tag1Value = "yes,no,not-applicable"
    tag2Key   = "ExportFormat"
    tag2Value = "json,csv,xml,structured"
    tag3Key   = "DataSubjectAccess"
    tag3Value = "enabled,disabled"
  })

  scope {
    compliance_resource_types = [
      "AWS::S3::Bucket",
      "AWS::RDS::DBInstance",
      "AWS::DynamoDB::Table"
    ]
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "gdpr-data-portability"
    ComplianceFramework = "UK-GDPR"
    Article             = "Article 20"
    Principle           = "Data Portability"
  })
}

# GDPR Lawfulness of Processing (Article 6)
resource "aws_config_config_rule" "gdpr_lawfulness_of_processing" {
  count = var.enable_gdpr_pack ? 1 : 0

  name = "gdpr-lawfulness-of-processing"

  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }

  input_parameters = jsonencode({
    tag1Key   = "LegalBasisArticle6"
    tag1Value = "consent,contract,legal-obligation,vital-interests,public-task,legitimate-interests"
    tag2Key   = "ConsentMechanism"
    tag2Value = "explicit,implied,not-applicable"
    tag3Key   = "ProcessingLawfulness"
    tag3Value = "verified,pending-verification"
  })

  scope {
    compliance_resource_types = [
      "AWS::S3::Bucket",
      "AWS::RDS::DBInstance",
      "AWS::DynamoDB::Table",
      "AWS::EFS::FileSystem"
    ]
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "gdpr-lawfulness-of-processing"
    ComplianceFramework = "UK-GDPR"
    Article             = "Article 6"
    Principle           = "Lawfulness of Processing"
  })
}

# GDPR Data Minimization (Article 5)
resource "aws_config_config_rule" "gdpr_data_minimization" {
  count = var.enable_gdpr_pack ? 1 : 0

  name = "gdpr-data-minimization"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LIFECYCLE_CONFIGURATION_RULE"
  }

  scope {
    compliance_resource_types = [
      "AWS::S3::Bucket"
    ]
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "gdpr-data-minimization"
    ComplianceFramework = "UK-GDPR"
    Article             = "Article 5"
    Principle           = "Data Minimization"
  })
}

# GDPR Cross-Border Data Transfer Restrictions
resource "aws_config_config_rule" "gdpr_cross_border_transfers" {
  count = var.enable_gdpr_pack ? 1 : 0

  name = "gdpr-cross-border-data-transfers"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_CROSS_REGION_REPLICATION_ENABLED"
  }

  input_parameters = jsonencode({
    allowedDestinationRegions = "us-west-2,us-east-1"
  })

  scope {
    compliance_resource_types = [
      "AWS::S3::Bucket"
    ]
  }

  depends_on = [var.config_recorder_dependency]

  tags = merge(var.common_tags, {
    Name                = "gdpr-cross-border-data-transfers"
    ComplianceFramework = "UK-GDPR"
    Article             = "Article 44-49"
    Principle           = "International Transfers"
  })
}
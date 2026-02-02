# Organization Structure Module
# Implements AWS Organizations with region-specific organizational units and service control policies

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Data source to get the current organization
data "aws_organizations_organization" "current" {}

# Create organizational units for region-specific environments
resource "aws_organizations_organizational_unit" "production_uk" {
  name      = "Production-UK"
  parent_id = data.aws_organizations_organization.current.roots[0].id

  tags = merge(var.common_tags, {
    Name               = "Production-UK"
    Environment        = "production"
    DataClassification = "confidential"
    Purpose            = "Production workloads for UK operations"
  })
}

resource "aws_organizations_organizational_unit" "non_production_uk" {
  name      = "Non-Production-UK"
  parent_id = data.aws_organizations_organization.current.roots[0].id

  tags = merge(var.common_tags, {
    Name               = "Non-Production-UK"
    Environment        = "non-production"
    DataClassification = "internal"
    Purpose            = "Development and testing environments for UK operations"
  })
}

resource "aws_organizations_organizational_unit" "sandbox" {
  name      = "Sandbox"
  parent_id = data.aws_organizations_organization.current.roots[0].id

  tags = merge(var.common_tags, {
    Name               = "Sandbox"
    Environment        = "sandbox"
    DataClassification = "internal"
    Purpose            = "Experimentation and proof-of-concept environments"
  })
}

# Create organizational unit for core infrastructure accounts
resource "aws_organizations_organizational_unit" "core_infrastructure" {
  name      = "Core-Infrastructure"
  parent_id = data.aws_organizations_organization.current.roots[0].id

  tags = merge(var.common_tags, {
    Name               = "Core-Infrastructure"
    Environment        = "infrastructure"
    DataClassification = "restricted"
    Purpose            = "Core infrastructure accounts (Security, Logging, Networking)"
  })
}

# Service Control Policies
# UK Data Residency Policy
resource "aws_organizations_policy" "uk_data_residency" {
  count = var.enable_service_control_policies ? 1 : 0

  name        = "UK-Data-Residency-Policy"
  description = "Enforces UK data residency by restricting AWS services to specified regions (us-west-2, us-east-1)"
  type        = "SERVICE_CONTROL_POLICY"
  content     = file("${var.policy_path}/uk-data-residency.json")

  tags = merge(var.common_tags, {
    Name       = "UK-Data-Residency-Policy"
    PolicyType = "SERVICE_CONTROL_POLICY"
    Purpose    = "UK Data Residency Enforcement"
    Compliance = "UK-GDPR"
  })
}

# Mandatory Tagging Policy
resource "aws_organizations_policy" "mandatory_tagging" {
  count = var.enable_service_control_policies ? 1 : 0

  name        = "UK-Mandatory-Tagging-Policy"
  description = "Enforces mandatory tagging for compliance including DataClassification, Environment, CostCenter, and Owner tags"
  type        = "SERVICE_CONTROL_POLICY"
  content     = file("${var.policy_path}/mandatory-tagging.json")

  tags = merge(var.common_tags, {
    Name       = "UK-Mandatory-Tagging-Policy"
    PolicyType = "SERVICE_CONTROL_POLICY"
    Purpose    = "Mandatory Resource Tagging"
    Compliance = "UK-Cost-Management"
  })
}

# Service Restrictions Policy
resource "aws_organizations_policy" "service_restrictions" {
  count = var.enable_service_control_policies ? 1 : 0

  name        = "UK-Service-Restrictions-Policy"
  description = "Restricts access to high-risk AWS services and prevents disabling of security controls like CloudTrail, Config, and GuardDuty"
  type        = "SERVICE_CONTROL_POLICY"
  content     = file("${var.policy_path}/service-restrictions.json")

  tags = merge(var.common_tags, {
    Name       = "UK-Service-Restrictions-Policy"
    PolicyType = "SERVICE_CONTROL_POLICY"
    Purpose    = "Service Access Control"
    Compliance = "Security Standards-Cloud-Security-Principles"
  })
}

# IAM Hardening Policy
resource "aws_organizations_policy" "iam_hardening" {
  count = var.enable_service_control_policies ? 1 : 0

  name        = "UK-IAM-Hardening-Policy"
  description = "Enforces IAM security best practices including MFA requirements, role protection, and prevents creation of overly permissive policies"
  type        = "SERVICE_CONTROL_POLICY"
  content     = file("${var.policy_path}/iam-hardening.json")

  tags = merge(var.common_tags, {
    Name       = "UK-IAM-Hardening-Policy"
    PolicyType = "SERVICE_CONTROL_POLICY"
    Purpose    = "IAM Security Hardening"
    Compliance = "Security Standards-Personnel-Security"
  })
}

# Policy Attachments
# UK Data Residency Policy Attachments
resource "aws_organizations_policy_attachment" "uk_data_residency_production" {
  count = var.enable_service_control_policies ? 1 : 0

  policy_id = aws_organizations_policy.uk_data_residency[0].id
  target_id = aws_organizations_organizational_unit.production_uk.id
}

resource "aws_organizations_policy_attachment" "uk_data_residency_non_production" {
  count = var.enable_service_control_policies ? 1 : 0

  policy_id = aws_organizations_policy.uk_data_residency[0].id
  target_id = aws_organizations_organizational_unit.non_production_uk.id
}

resource "aws_organizations_policy_attachment" "uk_data_residency_sandbox" {
  count = var.enable_service_control_policies ? 1 : 0

  policy_id = aws_organizations_policy.uk_data_residency[0].id
  target_id = aws_organizations_organizational_unit.sandbox.id
}

resource "aws_organizations_policy_attachment" "uk_data_residency_core_infrastructure" {
  count = var.enable_service_control_policies ? 1 : 0

  policy_id = aws_organizations_policy.uk_data_residency[0].id
  target_id = aws_organizations_organizational_unit.core_infrastructure.id
}

# Mandatory Tagging Policy Attachments
resource "aws_organizations_policy_attachment" "mandatory_tagging_production" {
  count = var.enable_service_control_policies ? 1 : 0

  policy_id = aws_organizations_policy.mandatory_tagging[0].id
  target_id = aws_organizations_organizational_unit.production_uk.id
}

resource "aws_organizations_policy_attachment" "mandatory_tagging_non_production" {
  count = var.enable_service_control_policies ? 1 : 0

  policy_id = aws_organizations_policy.mandatory_tagging[0].id
  target_id = aws_organizations_organizational_unit.non_production_uk.id
}

resource "aws_organizations_policy_attachment" "mandatory_tagging_sandbox" {
  count = var.enable_service_control_policies ? 1 : 0

  policy_id = aws_organizations_policy.mandatory_tagging[0].id
  target_id = aws_organizations_organizational_unit.sandbox.id
}

resource "aws_organizations_policy_attachment" "mandatory_tagging_core_infrastructure" {
  count = var.enable_service_control_policies ? 1 : 0

  policy_id = aws_organizations_policy.mandatory_tagging[0].id
  target_id = aws_organizations_organizational_unit.core_infrastructure.id
}

# Service Restrictions Policy Attachments
resource "aws_organizations_policy_attachment" "service_restrictions_production" {
  count = var.enable_service_control_policies ? 1 : 0

  policy_id = aws_organizations_policy.service_restrictions[0].id
  target_id = aws_organizations_organizational_unit.production_uk.id
}

resource "aws_organizations_policy_attachment" "service_restrictions_non_production" {
  count = var.enable_service_control_policies ? 1 : 0

  policy_id = aws_organizations_policy.service_restrictions[0].id
  target_id = aws_organizations_organizational_unit.non_production_uk.id
}

# Note: Service restrictions are not applied to Sandbox to allow experimentation

resource "aws_organizations_policy_attachment" "service_restrictions_core_infrastructure" {
  count = var.enable_service_control_policies ? 1 : 0

  policy_id = aws_organizations_policy.service_restrictions[0].id
  target_id = aws_organizations_organizational_unit.core_infrastructure.id
}

# IAM Hardening Policy Attachments
resource "aws_organizations_policy_attachment" "iam_hardening_production" {
  count = var.enable_service_control_policies ? 1 : 0

  policy_id = aws_organizations_policy.iam_hardening[0].id
  target_id = aws_organizations_organizational_unit.production_uk.id
}

resource "aws_organizations_policy_attachment" "iam_hardening_non_production" {
  count = var.enable_service_control_policies ? 1 : 0

  policy_id = aws_organizations_policy.iam_hardening[0].id
  target_id = aws_organizations_organizational_unit.non_production_uk.id
}

resource "aws_organizations_policy_attachment" "iam_hardening_sandbox" {
  count = var.enable_service_control_policies ? 1 : 0

  policy_id = aws_organizations_policy.iam_hardening[0].id
  target_id = aws_organizations_organizational_unit.sandbox.id
}

resource "aws_organizations_policy_attachment" "iam_hardening_core_infrastructure" {
  count = var.enable_service_control_policies ? 1 : 0

  policy_id = aws_organizations_policy.iam_hardening[0].id
  target_id = aws_organizations_organizational_unit.core_infrastructure.id
}
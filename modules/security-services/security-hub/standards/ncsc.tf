# Security Standards Cloud Security Principles Implementation for Security Hub
# This module implements Security Standards-specific security controls and custom insights

# Custom insight for Security Standards compliance violations
resource "aws_securityhub_insight" "ncsc_compliance_violations" {
  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }

    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }

    # Focus on region-specific compliance requirements
    title {
      comparison = "PREFIX"
      value      = "Security Standards"
    }
  }

  group_by_attribute = "ComplianceStatus"
  name               = "Security Standards Cloud Security Principles Violations"
}

# Custom insight for data protection violations (Security Standards Principle 2)
resource "aws_securityhub_insight" "data_protection_violations" {
  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }

    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }

    # Focus on encryption and data protection findings
    title {
      comparison = "CONTAINS"
      value      = "encryption"
    }
  }

  group_by_attribute = "ResourceType"
  name               = "Security Standards Data Protection Violations"
}

# Custom insight for asset protection violations (Security Standards Principle 3)
resource "aws_securityhub_insight" "asset_protection_violations" {
  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }

    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }

    # Focus on backup, resilience, and availability findings
    title {
      comparison = "CONTAINS"
      value      = "backup"
    }
  }

  group_by_attribute = "ResourceType"
  name               = "Security Standards Asset Protection Violations"
}

# Custom insight for separation violations (Security Standards Principle 4)
resource "aws_securityhub_insight" "separation_violations" {
  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }

    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }

    # Focus on IAM and access control findings
    resource_type {
      comparison = "EQUALS"
      value      = "AwsIamRole"
    }
  }

  group_by_attribute = "ResourceId"
  name               = "Security Standards User Separation Violations"
}

# Custom insight for governance violations (Security Standards Principle 5)
resource "aws_securityhub_insight" "governance_violations" {
  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }

    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }

    # Focus on policy and governance findings
    title {
      comparison = "CONTAINS"
      value      = "policy"
    }
  }

  group_by_attribute = "ComplianceStatus"
  name               = "Security Standards Governance Framework Violations"
}

# Custom insight for operational security violations (Security Standards Principle 6)
resource "aws_securityhub_insight" "operational_security_violations" {
  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }

    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }

    # Focus on logging and monitoring findings
    resource_type {
      comparison = "PREFIX"
      value      = "AwsCloudTrail"
    }
  }

  group_by_attribute = "ResourceType"
  name               = "Security Standards Operational Security Violations"
}

# Custom insight for personnel security violations (Security Standards Principle 7)
resource "aws_securityhub_insight" "personnel_security_violations" {
  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }

    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }

    # Focus on MFA and access control findings
    title {
      comparison = "CONTAINS"
      value      = "MFA"
    }
  }

  group_by_attribute = "ResourceId"
  name               = "Security Standards Personnel Security Violations"
}

# Custom action for Security Standards compliance remediation
resource "aws_securityhub_action_target" "ncsc_remediation" {
  name        = "Security Standards Compliance"
  identifier  = "ncscCompliance"
  description = "Trigger automated remediation for Security Standards compliance violations"
}

# region-specific compliance dashboard insight
resource "aws_securityhub_insight" "uk_compliance_overview" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }

    # Filter for region-specific resources and compliance
    resource_region {
      comparison = "EQUALS"
      value      = var.aws_region
    }
  }

  group_by_attribute = "ComplianceStatus"
  name               = "UK Compliance Overview"
}
# CIS AWS Foundations Benchmark Implementation for Security Hub
# This module implements CIS benchmark controls and monitoring

# Enable CIS AWS Foundations Benchmark v1.4.0
resource "aws_securityhub_standards_subscription" "cis_benchmark" {
  count         = var.enable_cis_standard ? 1 : 0
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/cis-aws-foundations-benchmark/v/1.4.0"
  depends_on    = [var.security_hub_account_dependency]
}

# Custom insight for CIS critical findings
resource "aws_securityhub_insight" "cis_critical_findings" {
  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }

    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }

    severity_label {
      comparison = "EQUALS"
      value      = "CRITICAL"
    }

    # Focus on CIS benchmark findings
    generator_id {
      comparison = "PREFIX"
      value      = "arn:aws:securityhub:::ruleset/finding-format/cis-aws-foundations-benchmark"
    }
  }

  group_by_attribute = "SeverityLabel"
  name               = "CIS Critical Security Findings"
}

# Custom insight for CIS IAM findings
resource "aws_securityhub_insight" "cis_iam_findings" {
  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }

    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }

    # Focus on IAM-related CIS findings
    resource_type {
      comparison = "PREFIX"
      value      = "AwsIam"
    }

    generator_id {
      comparison = "PREFIX"
      value      = "arn:aws:securityhub:::ruleset/finding-format/cis-aws-foundations-benchmark"
    }
  }

  group_by_attribute = "ResourceType"
  name               = "CIS IAM Security Findings"
}

# Custom insight for CIS logging and monitoring findings
resource "aws_securityhub_insight" "cis_logging_findings" {
  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }

    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }

    # Focus on logging and monitoring CIS findings
    resource_type {
      comparison = "EQUALS"
      value      = "AwsCloudTrailTrail"
    }

    generator_id {
      comparison = "PREFIX"
      value      = "arn:aws:securityhub:::ruleset/finding-format/cis-aws-foundations-benchmark"
    }
  }

  group_by_attribute = "ResourceId"
  name               = "CIS Logging and Monitoring Findings"
}

# Custom insight for CIS networking findings
resource "aws_securityhub_insight" "cis_networking_findings" {
  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }

    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }

    # Focus on networking CIS findings
    resource_type {
      comparison = "PREFIX"
      value      = "AwsEc2"
    }

    generator_id {
      comparison = "PREFIX"
      value      = "arn:aws:securityhub:::ruleset/finding-format/cis-aws-foundations-benchmark"
    }
  }

  group_by_attribute = "ResourceType"
  name               = "CIS Networking Security Findings"
}

# Custom insight for CIS storage findings
resource "aws_securityhub_insight" "cis_storage_findings" {
  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }

    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }

    # Focus on storage CIS findings
    resource_type {
      comparison = "PREFIX"
      value      = "AwsS3"
    }

    generator_id {
      comparison = "PREFIX"
      value      = "arn:aws:securityhub:::ruleset/finding-format/cis-aws-foundations-benchmark"
    }
  }

  group_by_attribute = "ResourceType"
  name               = "CIS Storage Security Findings"
}

# Custom action for CIS remediation
resource "aws_securityhub_action_target" "cis_remediation" {
  name        = "CIS Benchmark"
  identifier  = "cisBenchmark"
  description = "Trigger automated remediation for CIS benchmark violations"
}

# CIS compliance summary insight
resource "aws_securityhub_insight" "cis_compliance_summary" {
  filters {
    generator_id {
      comparison = "PREFIX"
      value      = "arn:aws:securityhub:::ruleset/finding-format/cis-aws-foundations-benchmark"
    }

    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  group_by_attribute = "ComplianceStatus"
  name               = "CIS Benchmark Compliance Summary"
}

# region-specific CIS controls insight
resource "aws_securityhub_insight" "uk_cis_controls" {
  filters {
    generator_id {
      comparison = "PREFIX"
      value      = "arn:aws:securityhub:::ruleset/finding-format/cis-aws-foundations-benchmark"
    }

    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }

    # Filter for specified regions only
    resource_region {
      comparison = "EQUALS"
      value      = var.aws_region
    }
  }

  group_by_attribute = "SeverityLabel"
  name               = "UK CIS Controls Status"
}
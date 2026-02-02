# AWS Foundational Security Best Practices Implementation for Security Hub
# This module implements AWS foundational security controls and monitoring

# Enable AWS Foundational Security Best Practices v1.0.0
resource "aws_securityhub_standards_subscription" "aws_foundational" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [var.security_hub_account_dependency]
}

# Custom insight for AWS foundational critical findings
resource "aws_securityhub_insight" "aws_foundational_critical" {
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

    # Focus on AWS foundational security findings
    generator_id {
      comparison = "PREFIX"
      value      = "arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-best-practices"
    }
  }

  group_by_attribute = "ResourceType"
  name               = "AWS Foundational Critical Findings"
}

# Custom insight for AWS foundational high findings
resource "aws_securityhub_insight" "aws_foundational_high" {
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
      value      = "HIGH"
    }

    generator_id {
      comparison = "PREFIX"
      value      = "arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-best-practices"
    }
  }

  group_by_attribute = "ResourceType"
  name               = "AWS Foundational High Severity Findings"
}

# Custom insight for EC2 security findings
resource "aws_securityhub_insight" "aws_foundational_ec2" {
  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }

    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }

    # Focus on EC2-related findings
    resource_type {
      comparison = "PREFIX"
      value      = "AwsEc2"
    }

    generator_id {
      comparison = "PREFIX"
      value      = "arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-best-practices"
    }
  }

  group_by_attribute = "ResourceType"
  name               = "AWS Foundational EC2 Security Findings"
}

# Custom insight for S3 security findings
resource "aws_securityhub_insight" "aws_foundational_s3" {
  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }

    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }

    # Focus on S3-related findings
    resource_type {
      comparison = "PREFIX"
      value      = "AwsS3"
    }

    generator_id {
      comparison = "PREFIX"
      value      = "arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-best-practices"
    }
  }

  group_by_attribute = "ResourceId"
  name               = "AWS Foundational S3 Security Findings"
}

# Custom insight for RDS security findings
resource "aws_securityhub_insight" "aws_foundational_rds" {
  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }

    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }

    # Focus on RDS-related findings
    resource_type {
      comparison = "PREFIX"
      value      = "AwsRds"
    }

    generator_id {
      comparison = "PREFIX"
      value      = "arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-best-practices"
    }
  }

  group_by_attribute = "ResourceType"
  name               = "AWS Foundational RDS Security Findings"
}

# Custom insight for Lambda security findings
resource "aws_securityhub_insight" "aws_foundational_lambda" {
  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }

    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }

    # Focus on Lambda-related findings
    resource_type {
      comparison = "PREFIX"
      value      = "AwsLambda"
    }

    generator_id {
      comparison = "PREFIX"
      value      = "arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-best-practices"
    }
  }

  group_by_attribute = "ResourceType"
  name               = "AWS Foundational Lambda Security Findings"
}

# Custom insight for IAM security findings
resource "aws_securityhub_insight" "aws_foundational_iam" {
  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }

    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }

    # Focus on IAM-related findings
    resource_type {
      comparison = "PREFIX"
      value      = "AwsIam"
    }

    generator_id {
      comparison = "PREFIX"
      value      = "arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-best-practices"
    }
  }

  group_by_attribute = "ResourceType"
  name               = "AWS Foundational IAM Security Findings"
}

# Custom action for AWS foundational remediation
resource "aws_securityhub_action_target" "aws_foundational_remediation" {
  name        = "AWS Foundational"
  identifier  = "awsFoundational"
  description = "Trigger automated remediation for AWS foundational security violations"
}

# AWS foundational compliance summary
resource "aws_securityhub_insight" "aws_foundational_summary" {
  filters {
    generator_id {
      comparison = "PREFIX"
      value      = "arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-best-practices"
    }

    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  group_by_attribute = "ComplianceStatus"
  name               = "AWS Foundational Security Summary"
}

# region-specific AWS foundational controls
resource "aws_securityhub_insight" "uk_aws_foundational_controls" {
  filters {
    generator_id {
      comparison = "PREFIX"
      value      = "arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-best-practices"
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
  name               = "UK AWS Foundational Controls Status"
}
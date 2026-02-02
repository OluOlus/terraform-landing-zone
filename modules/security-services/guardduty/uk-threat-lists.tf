# UK-Specific Threat Intelligence Lists for GuardDuty
# This configuration implements region-specific threat intelligence feeds
# and custom threat lists aligned with Security Standards guidance

# Government threat intelligence feed (configure with actual threat intelligence sources)
resource "aws_guardduty_threatintelset" "uk_government_threats" {
  count = var.enable_uk_threat_intelligence ? 1 : 0

  activate    = true
  detector_id = aws_guardduty_detector.main.id
  format      = "TXT"
  location    = var.uk_government_threat_list_location
  name        = "UK-Government-Threat-Intelligence"

  tags = merge(var.common_tags, {
    Name                = "uk-government-threat-intel"
    DataClassification  = "confidential"
    Source              = "UK-Government"
    ComplianceFramework = "Security Standards"
    ThreatIntelType     = "Government"
  })
}

# Security Standards-aligned threat intelligence for critical infrastructure
resource "aws_guardduty_threatintelset" "ncsc_critical_infrastructure" {
  count = var.enable_ncsc_threat_intelligence ? 1 : 0

  activate    = true
  detector_id = aws_guardduty_detector.main.id
  format      = "TXT"
  location    = var.ncsc_threat_list_location
  name        = "Security Standards-Critical-Infrastructure-Threats"

  tags = merge(var.common_tags, {
    Name                = "ncsc-critical-infrastructure-threats"
    DataClassification  = "confidential"
    Source              = "Security Standards"
    ComplianceFramework = "Security Standards"
    ThreatIntelType     = "CriticalInfrastructure"
  })
}

# UK financial services threat intelligence (for financial sector deployments)
resource "aws_guardduty_threatintelset" "uk_financial_threats" {
  count = var.enable_financial_threat_intelligence ? 1 : 0

  activate    = true
  detector_id = aws_guardduty_detector.main.id
  format      = "TXT"
  location    = var.financial_threat_list_location
  name        = "UK-Financial-Services-Threats"

  tags = merge(var.common_tags, {
    Name                = "uk-financial-threats"
    DataClassification  = "confidential"
    Source              = "UK-Financial-Regulators"
    ComplianceFramework = "FCA-PRA"
    ThreatIntelType     = "Financial"
  })
}

# UK healthcare threat intelligence (for NHS and healthcare deployments)
resource "aws_guardduty_threatintelset" "uk_healthcare_threats" {
  count = var.enable_healthcare_threat_intelligence ? 1 : 0

  activate    = true
  detector_id = aws_guardduty_detector.main.id
  format      = "TXT"
  location    = var.healthcare_threat_list_location
  name        = "UK-Healthcare-Threats"

  tags = merge(var.common_tags, {
    Name                = "uk-healthcare-threats"
    DataClassification  = "confidential"
    Source              = "NHS-Digital"
    ComplianceFramework = "NHS-Digital"
    ThreatIntelType     = "Healthcare"
  })
}

# Custom IP allow list for known UK government and partner networks
resource "aws_guardduty_ipset" "uk_government_allowlist" {
  count = var.enable_uk_government_allowlist ? 1 : 0

  activate    = true
  detector_id = aws_guardduty_detector.main.id
  format      = "TXT"
  location    = var.uk_government_allowlist_location
  name        = "UK-Government-IP-Allowlist"

  tags = merge(var.common_tags, {
    Name                = "uk-government-allowlist"
    DataClassification  = "internal"
    Source              = "UK-Government"
    ComplianceFramework = "Security Standards"
    ListType            = "Allowlist"
  })
}

# Custom IP block list for known malicious UK-targeting threats
resource "aws_guardduty_ipset" "uk_targeted_threats" {
  count = var.enable_uk_targeted_threats_blocklist ? 1 : 0

  activate    = true
  detector_id = aws_guardduty_detector.main.id
  format      = "TXT"
  location    = var.uk_targeted_threats_location
  name        = "UK-Targeted-Threats-Blocklist"

  tags = merge(var.common_tags, {
    Name                = "uk-targeted-threats-blocklist"
    DataClassification  = "confidential"
    Source              = "UK-Threat-Intelligence"
    ComplianceFramework = "Security Standards"
    ListType            = "Blocklist"
  })
}

# Brexit-related threat intelligence (for trade and customs systems)
resource "aws_guardduty_threatintelset" "brexit_related_threats" {
  count = var.enable_brexit_threat_intelligence ? 1 : 0

  activate    = true
  detector_id = aws_guardduty_detector.main.id
  format      = "TXT"
  location    = var.brexit_threat_list_location
  name        = "Brexit-Related-Threats"

  tags = merge(var.common_tags, {
    Name                = "brexit-related-threats"
    DataClassification  = "confidential"
    Source              = "HMRC-Border-Force"
    ComplianceFramework = "HMRC"
    ThreatIntelType     = "Trade-Customs"
  })
}

# UK critical national infrastructure (CNI) threat intelligence
resource "aws_guardduty_threatintelset" "uk_cni_threats" {
  count = var.enable_cni_threat_intelligence ? 1 : 0

  activate    = true
  detector_id = aws_guardduty_detector.main.id
  format      = "TXT"
  location    = var.cni_threat_list_location
  name        = "UK-CNI-Threats"

  tags = merge(var.common_tags, {
    Name                = "uk-cni-threats"
    DataClassification  = "restricted"
    Source              = "Security Standards-CNI"
    ComplianceFramework = "Security Standards-CNI"
    ThreatIntelType     = "CriticalInfrastructure"
  })
}

# Automated threat intelligence update Lambda function
resource "aws_lambda_function" "threat_intel_updater" {
  count = var.enable_automated_threat_intel_updates ? 1 : 0

  filename      = var.threat_intel_updater_zip_path
  function_name = "uk-guardduty-threat-intel-updater"
  role          = aws_iam_role.threat_intel_updater[0].arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 300

  environment {
    variables = {
      DETECTOR_ID                   = aws_guardduty_detector.main.id
      UK_GOVERNMENT_THREAT_LIST_URL = var.uk_government_threat_list_url
      NCSC_THREAT_LIST_URL          = var.ncsc_threat_list_url
      S3_BUCKET                     = var.threat_intel_s3_bucket
      KMS_KEY_ID                    = var.threat_intel_kms_key_id
    }
  }

  tags = merge(var.common_tags, {
    Name               = "uk-guardduty-threat-intel-updater"
    DataClassification = "confidential"
    Purpose            = "ThreatIntelligenceUpdates"
  })
}

# IAM role for threat intelligence updater Lambda
resource "aws_iam_role" "threat_intel_updater" {
  count = var.enable_automated_threat_intel_updates ? 1 : 0

  name = "uk-guardduty-threat-intel-updater-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.common_tags, {
    Name = "uk-guardduty-threat-intel-updater-role"
  })
}

# IAM policy for threat intelligence updater
resource "aws_iam_role_policy" "threat_intel_updater" {
  count = var.enable_automated_threat_intel_updates ? 1 : 0

  name = "uk-guardduty-threat-intel-updater-policy"
  role = aws_iam_role.threat_intel_updater[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "guardduty:CreateThreatIntelSet",
          "guardduty:UpdateThreatIntelSet",
          "guardduty:DeleteThreatIntelSet",
          "guardduty:ListThreatIntelSets",
          "guardduty:GetThreatIntelSet"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.uk_regions
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "${var.threat_intel_s3_bucket_arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = var.threat_intel_kms_key_arn
      }
    ]
  })
}

# CloudWatch Event Rule for automated threat intelligence updates
resource "aws_cloudwatch_event_rule" "threat_intel_update_schedule" {
  count = var.enable_automated_threat_intel_updates ? 1 : 0

  name                = "uk-guardduty-threat-intel-update"
  description         = "Trigger threat intelligence updates for UK GuardDuty"
  schedule_expression = var.threat_intel_update_schedule

  tags = merge(var.common_tags, {
    Name = "uk-guardduty-threat-intel-update-schedule"
  })
}

# CloudWatch Event Target for Lambda function
resource "aws_cloudwatch_event_target" "threat_intel_updater" {
  count = var.enable_automated_threat_intel_updates ? 1 : 0

  rule      = aws_cloudwatch_event_rule.threat_intel_update_schedule[0].name
  target_id = "ThreatIntelUpdaterTarget"
  arn       = aws_lambda_function.threat_intel_updater[0].arn
}

# Lambda permission for CloudWatch Events
resource "aws_lambda_permission" "allow_cloudwatch" {
  count = var.enable_automated_threat_intel_updates ? 1 : 0

  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.threat_intel_updater[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.threat_intel_update_schedule[0].arn
}
# AWS CloudWatch Monitoring Module
# Provides centralized monitoring, dashboards, and alarms

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# CloudWatch Dashboard for Security Posture
resource "aws_cloudwatch_dashboard" "security_posture" {
  dashboard_name = "${var.environment}-security-posture"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/SecurityHub", "Findings", "ComplianceType", "FAILED"],
            ["AWS/GuardDuty", "FindingCount"],
            ["AWS/Config", "ComplianceByConfigRule", "RuleName", "ALL"]
          ]
          period = 300
          stat   = "Sum"
          region = var.aws_region
          title  = "Security Findings Overview"
        }
      }
    ]
  })

  tags = var.tags
}

# CloudWatch Dashboard for Compliance
resource "aws_cloudwatch_dashboard" "compliance" {
  dashboard_name = "${var.environment}-compliance"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/Config", "ComplianceByConfigRule"],
            ["AWS/SecurityHub", "ComplianceScore"]
          ]
          period = 300
          stat   = "Average"
          region = var.aws_region
          title  = "Compliance Status"
        }
      }
    ]
  })

  tags = var.tags
}

# CloudWatch Dashboard for Cost Usage
resource "aws_cloudwatch_dashboard" "cost_usage" {
  dashboard_name = "${var.environment}-cost-usage"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/Billing", "EstimatedCharges", "Currency", "USD"]
          ]
          period = 86400
          stat   = "Maximum"
          region = "us-east-1"
          title  = "Daily Cost Trends"
        }
      }
    ]
  })

  tags = var.tags
}

# Security Hub Findings Alarm
resource "aws_cloudwatch_metric_alarm" "security_hub_critical_findings" {
  alarm_name          = "${var.environment}-security-hub-critical-findings"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Findings"
  namespace           = "AWS/SecurityHub"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "This metric monitors critical security findings"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  dimensions = {
    ComplianceType = "FAILED"
    SeverityLabel  = "CRITICAL"
  }

  tags = var.tags
}

# GuardDuty Findings Alarm
resource "aws_cloudwatch_metric_alarm" "guardduty_findings" {
  alarm_name          = "${var.environment}-guardduty-findings"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "FindingCount"
  namespace           = "AWS/GuardDuty"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "This metric monitors GuardDuty findings"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  tags = var.tags
}

# SNS Topic for Security Alerts
resource "aws_sns_topic" "security_alerts" {
  name = "${var.environment}-security-alerts"
  tags = var.tags
}

# SNS Topic Policy
resource "aws_sns_topic_policy" "security_alerts" {
  arn = aws_sns_topic.security_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.security_alerts.arn
      }
    ]
  })
}
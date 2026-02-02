# Cost Management Module - UK Landing Zone Cost Controls
# This module implements cost management and budgets for the UK AWS Secure Landing Zone

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# AWS Budgets
resource "aws_budgets_budget" "budgets" {
  for_each = var.budgets

  name              = each.key
  budget_type       = each.value.budget_type
  limit_amount      = each.value.limit_amount
  limit_unit        = each.value.limit_unit
  time_unit         = each.value.time_unit
  time_period_start = each.value.time_period_start
  time_period_end   = each.value.time_period_end

  dynamic "cost_filter" {
    for_each = each.value.cost_filters
    content {
      name   = cost_filter.key
      values = cost_filter.value
    }
  }

  dynamic "notification" {
    for_each = each.value.notifications
    content {
      comparison_operator        = notification.value.comparison_operator
      threshold                  = notification.value.threshold
      threshold_type             = notification.value.threshold_type
      notification_type          = notification.value.notification_type
      subscriber_email_addresses = notification.value.subscriber_email_addresses
      subscriber_sns_topic_arns  = notification.value.subscriber_sns_topic_arns
    }
  }
}

# Cost Anomaly Detector
resource "aws_ce_anomaly_monitor" "main" {
  count = var.enable_anomaly_detection ? 1 : 0

  name              = var.anomaly_monitor_name
  monitor_type      = var.anomaly_monitor_type
  monitor_dimension = var.anomaly_monitor_dimension

  tags = var.common_tags
}

# Cost Anomaly Subscription
resource "aws_ce_anomaly_subscription" "main" {
  count = var.enable_anomaly_detection ? 1 : 0

  name      = "${var.anomaly_monitor_name}-subscription"
  frequency = var.anomaly_subscription_frequency
  threshold_expression {
    dimension {
      key           = "ANOMALY_TOTAL_IMPACT_ABSOLUTE"
      values        = [tostring(var.anomaly_threshold_amount)]
      match_options = ["GREATER_THAN_OR_EQUAL"]
    }
  }

  monitor_arn_list = [aws_ce_anomaly_monitor.main[0].arn]

  dynamic "subscriber" {
    for_each = var.anomaly_subscriber_emails
    content {
      type    = "EMAIL"
      address = subscriber.value
    }
  }

  dynamic "subscriber" {
    for_each = var.anomaly_subscriber_sns_arns
    content {
      type    = "SNS"
      address = subscriber.value
    }
  }

  tags = var.common_tags
}

# Cost and Usage Report
resource "aws_cur_report_definition" "main" {
  count = var.enable_cost_usage_report ? 1 : 0

  report_name                = var.cur_report_name
  time_unit                  = "DAILY"
  format                     = "Parquet"
  compression                = "Parquet"
  additional_schema_elements = ["RESOURCES"]
  s3_bucket                  = var.cur_s3_bucket_name
  s3_region                  = var.cur_s3_region
  s3_prefix                  = var.cur_s3_prefix
  additional_artifacts       = ["ATHENA"]
  report_versioning          = "OVERWRITE_REPORT"
  refresh_closed_reports     = true
}

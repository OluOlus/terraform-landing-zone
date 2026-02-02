# CloudWatch Monitoring Module - UK Centralized Monitoring
# This module implements centralized CloudWatch monitoring for the UK AWS Secure Landing Zone

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# CloudWatch Log Groups for centralized logging
resource "aws_cloudwatch_log_group" "log_groups" {
  for_each = var.log_groups

  name              = each.value.name
  retention_in_days = each.value.retention_days
  kms_key_id        = each.value.kms_key_id

  tags = merge(var.common_tags, {
    Name               = each.key
    Purpose            = each.value.purpose
    DataClassification = "confidential"
  })
}

# CloudWatch Metric Alarms
resource "aws_cloudwatch_metric_alarm" "alarms" {
  for_each = var.metric_alarms

  alarm_name          = each.key
  comparison_operator = each.value.comparison_operator
  evaluation_periods  = each.value.evaluation_periods
  metric_name         = each.value.metric_name
  namespace           = each.value.namespace
  period              = each.value.period
  statistic           = each.value.statistic
  threshold           = each.value.threshold
  alarm_description   = each.value.description
  alarm_actions       = each.value.alarm_actions
  ok_actions          = each.value.ok_actions
  treat_missing_data  = each.value.treat_missing_data

  dimensions = each.value.dimensions

  tags = var.common_tags
}

# CloudWatch Dashboard
resource "aws_cloudwatch_dashboard" "main" {
  count          = var.create_dashboard ? 1 : 0
  dashboard_name = var.dashboard_name

  dashboard_body = jsonencode(var.dashboard_body)
}

# CloudWatch Composite Alarms
resource "aws_cloudwatch_composite_alarm" "composite_alarms" {
  for_each = var.composite_alarms

  alarm_name        = each.key
  alarm_description = each.value.description
  actions_enabled   = true
  alarm_actions     = each.value.alarm_actions
  ok_actions        = each.value.ok_actions
  alarm_rule        = each.value.alarm_rule

  tags = var.common_tags
}

# CloudWatch Event Rule (for automated responses)
resource "aws_cloudwatch_event_rule" "rules" {
  for_each = var.event_rules

  name          = each.key
  description   = each.value.description
  event_pattern = jsonencode(each.value.event_pattern)
  is_enabled    = each.value.is_enabled

  tags = var.common_tags
}

# CloudWatch Event Targets
resource "aws_cloudwatch_event_target" "targets" {
  for_each = var.event_targets

  rule      = aws_cloudwatch_event_rule.rules[each.value.rule_name].name
  target_id = each.key
  arn       = each.value.target_arn
  role_arn  = each.value.role_arn

  dynamic "input_transformer" {
    for_each = each.value.input_transformer != null ? [each.value.input_transformer] : []
    content {
      input_paths    = input_transformer.value.input_paths
      input_template = input_transformer.value.input_template
    }
  }
}

# SNS Topic for Alarms
resource "aws_sns_topic" "alarms" {
  count             = var.create_sns_topic ? 1 : 0
  name              = var.sns_topic_name
  kms_master_key_id = var.sns_kms_key_id

  tags = merge(var.common_tags, {
    Name    = var.sns_topic_name
    Purpose = "CloudWatch alarm notifications"
  })
}

# SNS Topic Subscription
resource "aws_sns_topic_subscription" "alarms" {
  for_each = var.create_sns_topic ? var.sns_subscriptions : {}

  topic_arn = aws_sns_topic.alarms[0].arn
  protocol  = each.value.protocol
  endpoint  = each.value.endpoint
}

# CloudWatch Insights Query Definitions
resource "aws_cloudwatch_query_definition" "queries" {
  for_each = var.insights_queries

  name            = each.key
  query_string    = each.value.query_string
  log_group_names = each.value.log_group_names
}

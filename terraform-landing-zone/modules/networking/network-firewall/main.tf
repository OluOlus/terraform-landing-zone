# AWS Network Firewall Module - UK Traffic Inspection
# This module implements centralized traffic inspection for the UK AWS Secure Landing Zone
# with support for Security Standards Cloud Security Principles and threat detection

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Network Firewall Policy
resource "aws_networkfirewall_firewall_policy" "main" {
  name = var.firewall_policy_name

  firewall_policy {
    # Stateless default actions
    stateless_default_actions          = var.stateless_default_actions
    stateless_fragment_default_actions = var.stateless_fragment_default_actions

    # Stateless rule group references
    dynamic "stateless_rule_group_reference" {
      for_each = var.stateless_rule_group_references
      content {
        priority     = stateless_rule_group_reference.value.priority
        resource_arn = stateless_rule_group_reference.value.resource_arn
      }
    }

    # Stateful rule group references
    dynamic "stateful_rule_group_reference" {
      for_each = var.stateful_rule_group_references
      content {
        resource_arn = stateful_rule_group_reference.value.resource_arn
        priority     = stateful_rule_group_reference.value.priority
        override {
          action = stateful_rule_group_reference.value.override_action
        }
      }
    }

    # Stateful engine options
    stateful_engine_options {
      rule_order = var.stateful_rule_order
    }

    # TLS inspection configuration
    dynamic "tls_inspection_configuration_arn" {
      for_each = var.tls_inspection_configuration_arn != null ? [1] : []
      content {
        resource_arn = var.tls_inspection_configuration_arn
      }
    }
  }

  tags = merge(var.common_tags, {
    Name               = var.firewall_policy_name
    Purpose            = "Network traffic inspection policy"
    DataClassification = "confidential"
    Compliance         = "Security Standards-CloudSecurityPrinciples"
  })
}

# Network Firewall
resource "aws_networkfirewall_firewall" "main" {
  name                              = var.firewall_name
  firewall_policy_arn               = aws_networkfirewall_firewall_policy.main.arn
  vpc_id                            = var.vpc_id
  delete_protection                 = var.delete_protection
  subnet_change_protection          = var.subnet_change_protection
  firewall_policy_change_protection = var.firewall_policy_change_protection

  # Subnet mappings for firewall endpoints
  dynamic "subnet_mapping" {
    for_each = var.subnet_mappings
    content {
      subnet_id = subnet_mapping.value
    }
  }

  tags = merge(var.common_tags, {
    Name               = var.firewall_name
    Purpose            = "Network traffic inspection"
    DataClassification = "confidential"
    Compliance         = "Security Standards-CloudSecurityPrinciples"
  })
}

# Stateless Rule Group for region-specific filtering
resource "aws_networkfirewall_rule_group" "uk_stateless_rules" {
  count    = var.create_uk_stateless_rules ? 1 : 0
  capacity = var.uk_stateless_rules_capacity
  name     = "${var.firewall_name}-uk-stateless-rules"
  type     = "STATELESS"

  rule_group {
    rules_source {
      stateless_rules_and_custom_actions {
        # Block traffic from non-specified regions (sample implementation)
        dynamic "stateless_rule" {
          for_each = var.uk_stateless_rules
          content {
            priority = stateless_rule.value.priority
            rule_definition {
              actions = stateless_rule.value.actions
              match_attributes {
                dynamic "source" {
                  for_each = stateless_rule.value.source_cidrs != null ? [1] : []
                  content {
                    address_definition = stateless_rule.value.source_cidrs
                  }
                }
                dynamic "destination" {
                  for_each = stateless_rule.value.destination_cidrs != null ? [1] : []
                  content {
                    address_definition = stateless_rule.value.destination_cidrs
                  }
                }
                dynamic "source_port" {
                  for_each = stateless_rule.value.source_ports != null ? stateless_rule.value.source_ports : []
                  content {
                    from_port = source_port.value.from_port
                    to_port   = source_port.value.to_port
                  }
                }
                dynamic "destination_port" {
                  for_each = stateless_rule.value.destination_ports != null ? stateless_rule.value.destination_ports : []
                  content {
                    from_port = destination_port.value.from_port
                    to_port   = destination_port.value.to_port
                  }
                }
                protocols = stateless_rule.value.protocols
              }
            }
          }
        }
      }
    }
  }

  tags = merge(var.common_tags, {
    Name    = "${var.firewall_name}-uk-stateless-rules"
    Purpose = "region-specific stateless filtering"
  })
}

# Stateful Rule Group for Threat Detection (Domain filtering)
resource "aws_networkfirewall_rule_group" "domain_filtering" {
  count    = var.enable_domain_filtering ? 1 : 0
  capacity = var.domain_filtering_capacity
  name     = "${var.firewall_name}-domain-filtering"
  type     = "STATEFUL"

  rule_group {
    rules_source {
      rules_source_list {
        generated_rules_type = "DENYLIST"
        target_types         = ["HTTP_HOST", "TLS_SNI"]
        targets              = var.blocked_domains
      }
    }

    # Stateful rule options
    stateful_rule_options {
      rule_order = var.stateful_rule_order
    }
  }

  tags = merge(var.common_tags, {
    Name    = "${var.firewall_name}-domain-filtering"
    Purpose = "Malicious domain blocking"
  })
}

# Stateful Rule Group for Suricata IDS/IPS
resource "aws_networkfirewall_rule_group" "suricata_ids" {
  count    = var.enable_suricata_rules ? 1 : 0
  capacity = var.suricata_rules_capacity
  name     = "${var.firewall_name}-suricata-ids"
  type     = "STATEFUL"

  rule_group {
    rules_source {
      rules_string = var.suricata_rules_string
    }

    # Stateful rule options
    stateful_rule_options {
      rule_order = var.stateful_rule_order
    }
  }

  tags = merge(var.common_tags, {
    Name    = "${var.firewall_name}-suricata-ids"
    Purpose = "Intrusion Detection/Prevention"
  })
}

# Stateful Rule Group for 5-tuple rules
resource "aws_networkfirewall_rule_group" "stateful_5tuple" {
  count    = var.enable_stateful_5tuple_rules ? 1 : 0
  capacity = var.stateful_5tuple_capacity
  name     = "${var.firewall_name}-stateful-5tuple"
  type     = "STATEFUL"

  rule_group {
    rules_source {
      dynamic "stateful_rule" {
        for_each = var.stateful_5tuple_rules
        content {
          action = stateful_rule.value.action
          header {
            destination      = stateful_rule.value.destination
            destination_port = stateful_rule.value.destination_port
            direction        = stateful_rule.value.direction
            protocol         = stateful_rule.value.protocol
            source           = stateful_rule.value.source
            source_port      = stateful_rule.value.source_port
          }
          rule_option {
            keyword  = "sid"
            settings = [stateful_rule.value.sid]
          }
        }
      }
    }

    # Stateful rule options
    stateful_rule_options {
      rule_order = var.stateful_rule_order
    }
  }

  tags = merge(var.common_tags, {
    Name    = "${var.firewall_name}-stateful-5tuple"
    Purpose = "Stateful traffic filtering"
  })
}

# CloudWatch Log Group for Alert Logs
resource "aws_cloudwatch_log_group" "alert_logs" {
  count             = var.enable_alert_logging ? 1 : 0
  name              = "/aws/networkfirewall/${var.firewall_name}/alert"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.log_kms_key_id

  tags = merge(var.common_tags, {
    Name               = "${var.firewall_name}-alert-logs"
    Purpose            = "Network firewall alert logs"
    DataClassification = "confidential"
  })
}

# CloudWatch Log Group for Flow Logs
resource "aws_cloudwatch_log_group" "flow_logs" {
  count             = var.enable_flow_logging ? 1 : 0
  name              = "/aws/networkfirewall/${var.firewall_name}/flow"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.log_kms_key_id

  tags = merge(var.common_tags, {
    Name               = "${var.firewall_name}-flow-logs"
    Purpose            = "Network firewall flow logs"
    DataClassification = "confidential"
  })
}

# Logging Configuration
resource "aws_networkfirewall_logging_configuration" "main" {
  count        = var.enable_alert_logging || var.enable_flow_logging ? 1 : 0
  firewall_arn = aws_networkfirewall_firewall.main.arn

  logging_configuration {
    # Alert logging
    dynamic "log_destination_config" {
      for_each = var.enable_alert_logging ? [1] : []
      content {
        log_destination = {
          logGroup = aws_cloudwatch_log_group.alert_logs[0].name
        }
        log_destination_type = "CloudWatchLogs"
        log_type             = "ALERT"
      }
    }

    # Flow logging
    dynamic "log_destination_config" {
      for_each = var.enable_flow_logging ? [1] : []
      content {
        log_destination = {
          logGroup = aws_cloudwatch_log_group.flow_logs[0].name
        }
        log_destination_type = "CloudWatchLogs"
        log_type             = "FLOW"
      }
    }

    # S3 logging
    dynamic "log_destination_config" {
      for_each = var.enable_s3_logging ? [1] : []
      content {
        log_destination = {
          bucketName = var.s3_logging_bucket_name
          prefix     = var.s3_logging_prefix
        }
        log_destination_type = "S3"
        log_type             = var.s3_log_type
      }
    }
  }
}

# Route Table for Firewall Subnet
resource "aws_route_table" "firewall_routes" {
  count  = var.create_firewall_routes ? 1 : 0
  vpc_id = var.vpc_id

  tags = merge(var.common_tags, {
    Name    = "${var.firewall_name}-firewall-routes"
    Purpose = "Routes for firewall subnets"
  })
}

# CloudWatch Alarms for Firewall Monitoring
resource "aws_cloudwatch_metric_alarm" "high_packet_drop_rate" {
  count               = var.enable_cloudwatch_alarms ? 1 : 0
  alarm_name          = "${var.firewall_name}-high-packet-drop-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DroppedPackets"
  namespace           = "AWS/NetworkFirewall"
  period              = 300
  statistic           = "Sum"
  threshold           = var.packet_drop_threshold
  alarm_description   = "High packet drop rate detected on Network Firewall"
  alarm_actions       = var.alarm_sns_topic_arns

  dimensions = {
    FirewallName = aws_networkfirewall_firewall.main.name
  }

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "high_rule_evaluation_failures" {
  count               = var.enable_cloudwatch_alarms ? 1 : 0
  alarm_name          = "${var.firewall_name}-high-rule-evaluation-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "InvalidDroppedPackets"
  namespace           = "AWS/NetworkFirewall"
  period              = 300
  statistic           = "Sum"
  threshold           = var.rule_evaluation_failure_threshold
  alarm_description   = "High rule evaluation failures on Network Firewall"
  alarm_actions       = var.alarm_sns_topic_arns

  dimensions = {
    FirewallName = aws_networkfirewall_firewall.main.name
  }

  tags = var.common_tags
}

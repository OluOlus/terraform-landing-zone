# DNS Route53 Resolver Module - UK Centralized DNS
# This module implements centralized DNS resolution for the UK AWS Secure Landing Zone
# with support for Security Standards Cloud Security Principles

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Route53 Resolver Endpoint - Inbound
resource "aws_route53_resolver_endpoint" "inbound" {
  count     = var.create_inbound_endpoint ? 1 : 0
  name      = "${var.resolver_name}-inbound"
  direction = "INBOUND"

  security_group_ids = var.inbound_security_group_ids

  dynamic "ip_address" {
    for_each = var.inbound_subnet_ids
    content {
      subnet_id = ip_address.value
      ip        = null
    }
  }

  tags = merge(var.common_tags, {
    Name    = "${var.resolver_name}-inbound"
    Purpose = "Inbound DNS resolution from on-premises"
  })
}

# Route53 Resolver Endpoint - Outbound
resource "aws_route53_resolver_endpoint" "outbound" {
  count     = var.create_outbound_endpoint ? 1 : 0
  name      = "${var.resolver_name}-outbound"
  direction = "OUTBOUND"

  security_group_ids = var.outbound_security_group_ids

  dynamic "ip_address" {
    for_each = var.outbound_subnet_ids
    content {
      subnet_id = ip_address.value
      ip        = null
    }
  }

  tags = merge(var.common_tags, {
    Name    = "${var.resolver_name}-outbound"
    Purpose = "Outbound DNS resolution to on-premises"
  })
}

# Route53 Resolver Rules for forwarding
resource "aws_route53_resolver_rule" "forward" {
  for_each = var.forwarding_rules

  domain_name = each.value.domain_name
  name        = each.key
  rule_type   = "FORWARD"

  resolver_endpoint_id = aws_route53_resolver_endpoint.outbound[0].id

  dynamic "target_ip" {
    for_each = each.value.target_ips
    content {
      ip   = target_ip.value.ip
      port = target_ip.value.port
    }
  }

  tags = merge(var.common_tags, {
    Name   = each.key
    Domain = each.value.domain_name
  })
}

# Route53 Resolver Rule Associations
resource "aws_route53_resolver_rule_association" "main" {
  for_each = var.resolver_rule_associations

  resolver_rule_id = each.value.resolver_rule_id != null ? each.value.resolver_rule_id : aws_route53_resolver_rule.forward[each.value.forwarding_rule_key].id
  vpc_id           = each.value.vpc_id
}

# Route53 Private Hosted Zones
resource "aws_route53_zone" "private" {
  for_each = var.private_zones

  name = each.value.domain_name

  dynamic "vpc" {
    for_each = each.value.vpc_associations
    content {
      vpc_id     = vpc.value.vpc_id
      vpc_region = vpc.value.vpc_region
    }
  }

  tags = merge(var.common_tags, {
    Name   = each.key
    Domain = each.value.domain_name
    Type   = "Private"
  })
}

# Route53 Zone Associations (for cross-account VPCs)
resource "aws_route53_zone_association" "cross_account" {
  for_each = var.cross_account_zone_associations

  zone_id = each.value.zone_id != null ? each.value.zone_id : aws_route53_zone.private[each.value.private_zone_key].zone_id
  vpc_id  = each.value.vpc_id
}

# Route53 Resolver Query Logging Configuration
resource "aws_route53_resolver_query_log_config" "main" {
  count = var.enable_query_logging ? 1 : 0

  name            = "${var.resolver_name}-query-logs"
  destination_arn = var.query_log_destination_arn

  tags = merge(var.common_tags, {
    Name    = "${var.resolver_name}-query-logs"
    Purpose = "DNS query logging"
  })
}

# Route53 Resolver Query Logging Association
resource "aws_route53_resolver_query_log_config_association" "main" {
  for_each = var.enable_query_logging ? var.query_log_vpc_associations : {}

  resolver_query_log_config_id = aws_route53_resolver_query_log_config.main[0].id
  resource_id                  = each.value
}

# CloudWatch Log Group for Query Logs (if using CloudWatch)
resource "aws_cloudwatch_log_group" "query_logs" {
  count             = var.enable_query_logging && var.query_log_destination_type == "cloudwatch" ? 1 : 0
  name              = "/aws/route53/${var.resolver_name}/query-logs"
  retention_in_days = var.query_log_retention_days
  kms_key_id        = var.query_log_kms_key_id

  tags = merge(var.common_tags, {
    Name               = "${var.resolver_name}-query-logs"
    Purpose            = "DNS query logs storage"
    DataClassification = "confidential"
  })
}

# Route53 Resolver DNS Firewall Rule Group
resource "aws_route53_resolver_firewall_rule_group" "main" {
  count = var.enable_dns_firewall ? 1 : 0
  name  = "${var.resolver_name}-firewall-rules"

  tags = merge(var.common_tags, {
    Name    = "${var.resolver_name}-firewall-rules"
    Purpose = "DNS firewall rules"
  })
}

# DNS Firewall Rules
resource "aws_route53_resolver_firewall_rule" "rules" {
  for_each = var.enable_dns_firewall ? var.dns_firewall_rules : {}

  name                    = each.key
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.main[0].id
  firewall_domain_list_id = each.value.domain_list_id
  priority                = each.value.priority
  action                  = each.value.action
  block_response          = each.value.block_response
  block_override_domain   = each.value.block_override_domain
  block_override_dns_type = each.value.block_override_dns_type
  block_override_ttl      = each.value.block_override_ttl
}

# DNS Firewall Rule Group Association
resource "aws_route53_resolver_firewall_rule_group_association" "main" {
  for_each = var.enable_dns_firewall ? var.dns_firewall_vpc_associations : {}

  name                   = "${var.resolver_name}-firewall-${each.key}"
  firewall_rule_group_id = aws_route53_resolver_firewall_rule_group.main[0].id
  vpc_id                 = each.value.vpc_id
  priority               = each.value.priority
  mutation_protection    = each.value.mutation_protection

  tags = merge(var.common_tags, {
    Name = "${var.resolver_name}-firewall-${each.key}"
  })
}

# CloudWatch Alarms for DNS monitoring
resource "aws_cloudwatch_metric_alarm" "query_volume" {
  count               = var.enable_dns_monitoring ? 1 : 0
  alarm_name          = "${var.resolver_name}-high-query-volume"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "InboundQueryVolume"
  namespace           = "AWS/Route53Resolver"
  period              = 300
  statistic           = "Sum"
  threshold           = var.query_volume_threshold
  alarm_description   = "High DNS query volume detected"
  alarm_actions       = var.alarm_sns_topic_arns

  dimensions = {
    EndpointId = var.create_inbound_endpoint ? aws_route53_resolver_endpoint.inbound[0].id : ""
  }

  tags = var.common_tags
}

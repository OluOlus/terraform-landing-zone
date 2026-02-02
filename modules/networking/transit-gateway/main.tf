# Transit Gateway Module - UK Hub-and-Spoke Architecture
# This module implements centralized network connectivity for the UK AWS Secure Landing Zone
# following Security Standards Cloud Security Principles for network architecture

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Transit Gateway - Central hub for network connectivity
resource "aws_ec2_transit_gateway" "main" {
  description                     = var.tgw_description
  amazon_side_asn                 = var.amazon_side_asn
  default_route_table_association = var.default_route_table_association
  default_route_table_propagation = var.default_route_table_propagation
  dns_support                     = "enable"
  vpn_ecmp_support                = var.vpn_ecmp_support
  auto_accept_shared_attachments  = var.auto_accept_shared_attachments

  tags = merge(var.common_tags, {
    Name               = var.tgw_name
    Purpose            = "Central network hub for UK landing zone"
    DataClassification = "confidential"
    Compliance         = "Security Standards-CloudSecurityPrinciples"
  })
}

# Transit Gateway VPC Attachments
resource "aws_ec2_transit_gateway_vpc_attachment" "attachments" {
  for_each = var.vpc_attachments

  subnet_ids                                      = each.value.subnet_ids
  transit_gateway_id                              = aws_ec2_transit_gateway.main.id
  vpc_id                                          = each.value.vpc_id
  dns_support                                     = "enable"
  ipv6_support                                    = "disable"
  appliance_mode_support                          = each.value.appliance_mode_support
  transit_gateway_default_route_table_association = each.value.default_route_table_association
  transit_gateway_default_route_table_propagation = each.value.default_route_table_propagation

  tags = merge(var.common_tags, {
    Name        = "${var.tgw_name}-attachment-${each.key}"
    VpcName     = each.key
    Environment = each.value.environment
  })
}

# Production Route Table
resource "aws_ec2_transit_gateway_route_table" "production" {
  count              = var.create_production_route_table ? 1 : 0
  transit_gateway_id = aws_ec2_transit_gateway.main.id

  tags = merge(var.common_tags, {
    Name        = "${var.tgw_name}-production-rt"
    Environment = "production"
    Purpose     = "Production workload routing"
  })
}

# Non-Production Route Table
resource "aws_ec2_transit_gateway_route_table" "non_production" {
  count              = var.create_non_production_route_table ? 1 : 0
  transit_gateway_id = aws_ec2_transit_gateway.main.id

  tags = merge(var.common_tags, {
    Name        = "${var.tgw_name}-non-production-rt"
    Environment = "non-production"
    Purpose     = "Non-production workload routing"
  })
}

# Shared Services Route Table
resource "aws_ec2_transit_gateway_route_table" "shared_services" {
  count              = var.create_shared_services_route_table ? 1 : 0
  transit_gateway_id = aws_ec2_transit_gateway.main.id

  tags = merge(var.common_tags, {
    Name        = "${var.tgw_name}-shared-services-rt"
    Environment = "shared"
    Purpose     = "Shared services routing (DNS, logging, security)"
  })
}

# Sandbox Route Table (isolated)
resource "aws_ec2_transit_gateway_route_table" "sandbox" {
  count              = var.create_sandbox_route_table ? 1 : 0
  transit_gateway_id = aws_ec2_transit_gateway.main.id

  tags = merge(var.common_tags, {
    Name        = "${var.tgw_name}-sandbox-rt"
    Environment = "sandbox"
    Purpose     = "Isolated sandbox routing"
  })
}

# Route Table Associations
resource "aws_ec2_transit_gateway_route_table_association" "associations" {
  for_each = var.route_table_associations

  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.attachments[each.value.vpc_attachment_key].id
  transit_gateway_route_table_id = local.route_table_ids[each.value.route_table_name]
}

# Route Table Propagations
resource "aws_ec2_transit_gateway_route_table_propagation" "propagations" {
  for_each = var.route_table_propagations

  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.attachments[each.value.vpc_attachment_key].id
  transit_gateway_route_table_id = local.route_table_ids[each.value.route_table_name]
}

# Static Routes
resource "aws_ec2_transit_gateway_route" "static_routes" {
  for_each = var.static_routes

  destination_cidr_block         = each.value.destination_cidr_block
  transit_gateway_route_table_id = local.route_table_ids[each.value.route_table_name]
  transit_gateway_attachment_id  = each.value.attachment_id != null ? each.value.attachment_id : aws_ec2_transit_gateway_vpc_attachment.attachments[each.value.vpc_attachment_key].id
  blackhole                      = each.value.blackhole
}

# VPN Attachment
resource "aws_vpn_connection" "on_premises" {
  count = var.enable_vpn_attachment ? 1 : 0

  customer_gateway_id = var.customer_gateway_id
  transit_gateway_id  = aws_ec2_transit_gateway.main.id
  type                = "ipsec.1"
  static_routes_only  = var.vpn_static_routes_only

  tunnel1_inside_cidr   = var.vpn_tunnel1_inside_cidr
  tunnel1_preshared_key = var.vpn_tunnel1_preshared_key
  tunnel2_inside_cidr   = var.vpn_tunnel2_inside_cidr
  tunnel2_preshared_key = var.vpn_tunnel2_preshared_key

  tags = merge(var.common_tags, {
    Name    = "${var.tgw_name}-vpn-on-premises"
    Purpose = "On-premises connectivity"
  })
}

# Resource Access Manager (RAM) Share for Cross-Account Access
resource "aws_ram_resource_share" "tgw_share" {
  count                     = var.enable_ram_share ? 1 : 0
  name                      = "${var.tgw_name}-share"
  allow_external_principals = false

  tags = merge(var.common_tags, {
    Name    = "${var.tgw_name}-ram-share"
    Purpose = "Cross-account Transit Gateway sharing"
  })
}

# RAM Resource Association
resource "aws_ram_resource_association" "tgw" {
  count              = var.enable_ram_share ? 1 : 0
  resource_arn       = aws_ec2_transit_gateway.main.arn
  resource_share_arn = aws_ram_resource_share.tgw_share[0].arn
}

# RAM Principal Associations (share with specific accounts or OU)
resource "aws_ram_principal_association" "accounts" {
  for_each = var.enable_ram_share ? toset(var.ram_principal_associations) : toset([])

  principal          = each.value
  resource_share_arn = aws_ram_resource_share.tgw_share[0].arn
}

# Flow Logs for Transit Gateway
resource "aws_flow_log" "tgw_flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  log_destination      = var.flow_logs_destination_arn
  log_destination_type = var.flow_logs_destination_type
  traffic_type         = "ALL"
  transit_gateway_id   = aws_ec2_transit_gateway.main.id

  tags = merge(var.common_tags, {
    Name    = "${var.tgw_name}-flow-logs"
    Purpose = "Network traffic monitoring"
  })
}

# CloudWatch Log Group for Flow Logs (if using CloudWatch)
resource "aws_cloudwatch_log_group" "tgw_flow_logs" {
  count             = var.enable_flow_logs && var.flow_logs_destination_type == "cloud-watch-logs" ? 1 : 0
  name              = "/aws/transitgateway/${var.tgw_name}/flow-logs"
  retention_in_days = var.flow_logs_retention_days
  kms_key_id        = var.flow_logs_kms_key_id

  tags = merge(var.common_tags, {
    Name               = "${var.tgw_name}-flow-logs"
    Purpose            = "Transit Gateway flow logs storage"
    DataClassification = "confidential"
  })
}

# IAM Role for Flow Logs (if using CloudWatch)
resource "aws_iam_role" "flow_logs" {
  count = var.enable_flow_logs && var.flow_logs_destination_type == "cloud-watch-logs" ? 1 : 0
  name  = "${var.tgw_name}-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = var.common_tags
}

# IAM Policy for Flow Logs
resource "aws_iam_role_policy" "flow_logs" {
  count = var.enable_flow_logs && var.flow_logs_destination_type == "cloud-watch-logs" ? 1 : 0
  name  = "${var.tgw_name}-flow-logs-policy"
  role  = aws_iam_role.flow_logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

# Local values for route table ID mapping
locals {
  route_table_ids = merge(
    var.create_production_route_table ? { "production" = aws_ec2_transit_gateway_route_table.production[0].id } : {},
    var.create_non_production_route_table ? { "non_production" = aws_ec2_transit_gateway_route_table.non_production[0].id } : {},
    var.create_shared_services_route_table ? { "shared_services" = aws_ec2_transit_gateway_route_table.shared_services[0].id } : {},
    var.create_sandbox_route_table ? { "sandbox" = aws_ec2_transit_gateway_route_table.sandbox[0].id } : {}
  )
}

# Network Manager for monitoring and visualization (optional)
resource "aws_networkmanager_global_network" "main" {
  count       = var.enable_network_manager ? 1 : 0
  description = "Global network for ${var.tgw_name}"

  tags = merge(var.common_tags, {
    Name    = "${var.tgw_name}-global-network"
    Purpose = "Network monitoring and visualization"
  })
}

resource "aws_networkmanager_transit_gateway_registration" "main" {
  count               = var.enable_network_manager ? 1 : 0
  global_network_id   = aws_networkmanager_global_network.main[0].id
  transit_gateway_arn = aws_ec2_transit_gateway.main.arn
}

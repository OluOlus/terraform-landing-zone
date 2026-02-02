# Transit Gateway Module Outputs

# Core Transit Gateway Outputs
output "transit_gateway_id" {
  description = "ID of the Transit Gateway"
  value       = aws_ec2_transit_gateway.main.id
}

output "transit_gateway_arn" {
  description = "ARN of the Transit Gateway"
  value       = aws_ec2_transit_gateway.main.arn
}

output "transit_gateway_owner_id" {
  description = "Owner ID of the Transit Gateway"
  value       = aws_ec2_transit_gateway.main.owner_id
}

output "transit_gateway_association_default_route_table_id" {
  description = "ID of the default association route table"
  value       = aws_ec2_transit_gateway.main.association_default_route_table_id
}

output "transit_gateway_propagation_default_route_table_id" {
  description = "ID of the default propagation route table"
  value       = aws_ec2_transit_gateway.main.propagation_default_route_table_id
}

# VPC Attachment Outputs
output "vpc_attachment_ids" {
  description = "Map of VPC attachment IDs"
  value       = { for k, v in aws_ec2_transit_gateway_vpc_attachment.attachments : k => v.id }
}

output "vpc_attachment_details" {
  description = "Detailed information about VPC attachments"
  value = { for k, v in aws_ec2_transit_gateway_vpc_attachment.attachments : k => {
    id             = v.id
    vpc_id         = v.vpc_id
    subnet_ids     = v.subnet_ids
    appliance_mode = v.appliance_mode_support
    vpc_owner_id   = v.vpc_owner_id
  } }
}

# Route Table Outputs
output "production_route_table_id" {
  description = "ID of the production route table"
  value       = var.create_production_route_table ? aws_ec2_transit_gateway_route_table.production[0].id : null
}

output "non_production_route_table_id" {
  description = "ID of the non-production route table"
  value       = var.create_non_production_route_table ? aws_ec2_transit_gateway_route_table.non_production[0].id : null
}

output "shared_services_route_table_id" {
  description = "ID of the shared services route table"
  value       = var.create_shared_services_route_table ? aws_ec2_transit_gateway_route_table.shared_services[0].id : null
}

output "sandbox_route_table_id" {
  description = "ID of the sandbox route table"
  value       = var.create_sandbox_route_table ? aws_ec2_transit_gateway_route_table.sandbox[0].id : null
}

output "route_table_ids" {
  description = "Map of all route table IDs"
  value       = local.route_table_ids
}

# VPN Outputs
output "vpn_connection_id" {
  description = "ID of the VPN connection"
  value       = var.enable_vpn_attachment ? aws_vpn_connection.on_premises[0].id : null
}

output "vpn_connection_customer_gateway_configuration" {
  description = "Configuration information for the VPN connection"
  value       = var.enable_vpn_attachment ? aws_vpn_connection.on_premises[0].customer_gateway_configuration : null
  sensitive   = true
}

output "vpn_connection_tunnel1_address" {
  description = "Public IP address of VPN tunnel 1"
  value       = var.enable_vpn_attachment ? aws_vpn_connection.on_premises[0].tunnel1_address : null
}

output "vpn_connection_tunnel2_address" {
  description = "Public IP address of VPN tunnel 2"
  value       = var.enable_vpn_attachment ? aws_vpn_connection.on_premises[0].tunnel2_address : null
}

# RAM Share Outputs
output "ram_resource_share_id" {
  description = "ID of the RAM resource share"
  value       = var.enable_ram_share ? aws_ram_resource_share.tgw_share[0].id : null
}

output "ram_resource_share_arn" {
  description = "ARN of the RAM resource share"
  value       = var.enable_ram_share ? aws_ram_resource_share.tgw_share[0].arn : null
}

# Flow Logs Outputs
output "flow_log_id" {
  description = "ID of the Transit Gateway flow log"
  value       = var.enable_flow_logs ? aws_flow_log.tgw_flow_logs[0].id : null
}

output "flow_log_cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for flow logs"
  value       = var.enable_flow_logs && var.flow_logs_destination_type == "cloud-watch-logs" ? aws_cloudwatch_log_group.tgw_flow_logs[0].name : null
}

output "flow_log_cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch log group for flow logs"
  value       = var.enable_flow_logs && var.flow_logs_destination_type == "cloud-watch-logs" ? aws_cloudwatch_log_group.tgw_flow_logs[0].arn : null
}

# Network Manager Outputs
output "network_manager_global_network_id" {
  description = "ID of the Network Manager global network"
  value       = var.enable_network_manager ? aws_networkmanager_global_network.main[0].id : null
}

output "network_manager_global_network_arn" {
  description = "ARN of the Network Manager global network"
  value       = var.enable_network_manager ? aws_networkmanager_global_network.main[0].arn : null
}

# Summary Outputs
output "attachment_count" {
  description = "Number of VPC attachments"
  value       = length(aws_ec2_transit_gateway_vpc_attachment.attachments)
}

output "route_table_count" {
  description = "Number of route tables created"
  value = (
    (var.create_production_route_table ? 1 : 0) +
    (var.create_non_production_route_table ? 1 : 0) +
    (var.create_shared_services_route_table ? 1 : 0) +
    (var.create_sandbox_route_table ? 1 : 0)
  )
}

output "configuration_summary" {
  description = "Summary of Transit Gateway configuration"
  value = {
    tgw_id                  = aws_ec2_transit_gateway.main.id
    tgw_arn                 = aws_ec2_transit_gateway.main.arn
    vpc_attachments         = length(aws_ec2_transit_gateway_vpc_attachment.attachments)
    route_tables            = length(local.route_table_ids)
    vpn_enabled             = var.enable_vpn_attachment
    ram_sharing_enabled     = var.enable_ram_share
    flow_logs_enabled       = var.enable_flow_logs
    network_manager_enabled = var.enable_network_manager
  }
}

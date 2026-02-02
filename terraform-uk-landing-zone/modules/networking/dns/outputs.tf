# DNS Route53 Resolver Module Outputs

# Inbound Endpoint Outputs
output "inbound_endpoint_id" {
  description = "ID of the inbound resolver endpoint"
  value       = var.create_inbound_endpoint ? aws_route53_resolver_endpoint.inbound[0].id : null
}

output "inbound_endpoint_arn" {
  description = "ARN of the inbound resolver endpoint"
  value       = var.create_inbound_endpoint ? aws_route53_resolver_endpoint.inbound[0].arn : null
}

output "inbound_endpoint_ip_addresses" {
  description = "IP addresses of the inbound resolver endpoint"
  value       = var.create_inbound_endpoint ? aws_route53_resolver_endpoint.inbound[0].ip_address : null
}

# Outbound Endpoint Outputs
output "outbound_endpoint_id" {
  description = "ID of the outbound resolver endpoint"
  value       = var.create_outbound_endpoint ? aws_route53_resolver_endpoint.outbound[0].id : null
}

output "outbound_endpoint_arn" {
  description = "ARN of the outbound resolver endpoint"
  value       = var.create_outbound_endpoint ? aws_route53_resolver_endpoint.outbound[0].arn : null
}

# Forwarding Rules Outputs
output "forwarding_rule_ids" {
  description = "Map of forwarding rule names to rule IDs"
  value       = { for k, v in aws_route53_resolver_rule.forward : k => v.id }
}

output "forwarding_rule_arns" {
  description = "Map of forwarding rule names to rule ARNs"
  value       = { for k, v in aws_route53_resolver_rule.forward : k => v.arn }
}

# Private Zone Outputs
output "private_zone_ids" {
  description = "Map of private zone names to zone IDs"
  value       = { for k, v in aws_route53_zone.private : k => v.zone_id }
}

output "private_zone_name_servers" {
  description = "Map of private zone names to name servers"
  value       = { for k, v in aws_route53_zone.private : k => v.name_servers }
}

# Query Logging Outputs
output "query_log_config_id" {
  description = "ID of the query logging configuration"
  value       = var.enable_query_logging ? aws_route53_resolver_query_log_config.main[0].id : null
}

output "query_log_config_arn" {
  description = "ARN of the query logging configuration"
  value       = var.enable_query_logging ? aws_route53_resolver_query_log_config.main[0].arn : null
}

output "query_log_group_name" {
  description = "Name of the CloudWatch log group for query logs"
  value       = var.enable_query_logging && var.query_log_destination_type == "cloudwatch" ? aws_cloudwatch_log_group.query_logs[0].name : null
}

# DNS Firewall Outputs
output "dns_firewall_rule_group_id" {
  description = "ID of the DNS firewall rule group"
  value       = var.enable_dns_firewall ? aws_route53_resolver_firewall_rule_group.main[0].id : null
}

output "dns_firewall_rule_group_arn" {
  description = "ARN of the DNS firewall rule group"
  value       = var.enable_dns_firewall ? aws_route53_resolver_firewall_rule_group.main[0].arn : null
}

# Monitoring Outputs
output "query_volume_alarm_arn" {
  description = "ARN of the query volume CloudWatch alarm"
  value       = var.enable_dns_monitoring ? aws_cloudwatch_metric_alarm.query_volume[0].arn : null
}

# Configuration Summary
output "configuration_summary" {
  description = "Summary of DNS resolver configuration"
  value = {
    inbound_endpoint_enabled  = var.create_inbound_endpoint
    outbound_endpoint_enabled = var.create_outbound_endpoint
    forwarding_rules_count    = length(var.forwarding_rules)
    private_zones_count       = length(var.private_zones)
    query_logging_enabled     = var.enable_query_logging
    dns_firewall_enabled      = var.enable_dns_firewall
    monitoring_enabled        = var.enable_dns_monitoring
  }
}

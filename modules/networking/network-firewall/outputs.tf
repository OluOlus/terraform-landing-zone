# AWS Network Firewall Module Outputs

# Firewall Outputs
output "firewall_id" {
  description = "ID of the Network Firewall"
  value       = aws_networkfirewall_firewall.main.id
}

output "firewall_arn" {
  description = "ARN of the Network Firewall"
  value       = aws_networkfirewall_firewall.main.arn
}

output "firewall_name" {
  description = "Name of the Network Firewall"
  value       = aws_networkfirewall_firewall.main.name
}

output "firewall_status" {
  description = "Status of the Network Firewall"
  value       = aws_networkfirewall_firewall.main.firewall_status
}

output "firewall_endpoint_ids" {
  description = "List of firewall endpoint IDs"
  value       = [for endpoint in aws_networkfirewall_firewall.main.firewall_status[0].sync_states : endpoint.attachment[0].endpoint_id]
}

output "firewall_vpc_endpoints" {
  description = "Map of availability zones to VPC endpoint IDs"
  value = {
    for az, sync_state in aws_networkfirewall_firewall.main.firewall_status[0].sync_states :
    az => {
      endpoint_id = sync_state.attachment[0].endpoint_id
      subnet_id   = sync_state.attachment[0].subnet_id
      status      = sync_state.attachment[0].status
    }
  }
}

# Firewall Policy Outputs
output "firewall_policy_id" {
  description = "ID of the firewall policy"
  value       = aws_networkfirewall_firewall_policy.main.id
}

output "firewall_policy_arn" {
  description = "ARN of the firewall policy"
  value       = aws_networkfirewall_firewall_policy.main.arn
}

output "firewall_policy_name" {
  description = "Name of the firewall policy"
  value       = aws_networkfirewall_firewall_policy.main.name
}

# Rule Group Outputs
output "uk_stateless_rules_arn" {
  description = "ARN of UK stateless rules group"
  value       = var.create_uk_stateless_rules ? aws_networkfirewall_rule_group.uk_stateless_rules[0].arn : null
}

output "domain_filtering_rule_group_arn" {
  description = "ARN of domain filtering rule group"
  value       = var.enable_domain_filtering ? aws_networkfirewall_rule_group.domain_filtering[0].arn : null
}

output "suricata_ids_rule_group_arn" {
  description = "ARN of Suricata IDS rule group"
  value       = var.enable_suricata_rules ? aws_networkfirewall_rule_group.suricata_ids[0].arn : null
}

output "stateful_5tuple_rule_group_arn" {
  description = "ARN of stateful 5-tuple rule group"
  value       = var.enable_stateful_5tuple_rules ? aws_networkfirewall_rule_group.stateful_5tuple[0].arn : null
}

# Logging Outputs
output "alert_log_group_name" {
  description = "Name of CloudWatch log group for alerts"
  value       = var.enable_alert_logging ? aws_cloudwatch_log_group.alert_logs[0].name : null
}

output "alert_log_group_arn" {
  description = "ARN of CloudWatch log group for alerts"
  value       = var.enable_alert_logging ? aws_cloudwatch_log_group.alert_logs[0].arn : null
}

output "flow_log_group_name" {
  description = "Name of CloudWatch log group for flow logs"
  value       = var.enable_flow_logging ? aws_cloudwatch_log_group.flow_logs[0].name : null
}

output "flow_log_group_arn" {
  description = "ARN of CloudWatch log group for flow logs"
  value       = var.enable_flow_logging ? aws_cloudwatch_log_group.flow_logs[0].arn : null
}

# CloudWatch Alarms Outputs
output "high_packet_drop_alarm_arn" {
  description = "ARN of high packet drop CloudWatch alarm"
  value       = var.enable_cloudwatch_alarms ? aws_cloudwatch_metric_alarm.high_packet_drop_rate[0].arn : null
}

output "high_rule_evaluation_failure_alarm_arn" {
  description = "ARN of high rule evaluation failure CloudWatch alarm"
  value       = var.enable_cloudwatch_alarms ? aws_cloudwatch_metric_alarm.high_rule_evaluation_failures[0].arn : null
}

# Route Table Outputs
output "firewall_route_table_id" {
  description = "ID of the firewall route table"
  value       = var.create_firewall_routes ? aws_route_table.firewall_routes[0].id : null
}

# Configuration Summary
output "configuration_summary" {
  description = "Summary of Network Firewall configuration"
  value = {
    firewall_name             = aws_networkfirewall_firewall.main.name
    firewall_arn              = aws_networkfirewall_firewall.main.arn
    vpc_id                    = var.vpc_id
    endpoint_count            = length(aws_networkfirewall_firewall.main.firewall_status[0].sync_states)
    delete_protection         = var.delete_protection
    subnet_change_protection  = var.subnet_change_protection
    policy_change_protection  = var.firewall_policy_change_protection
    alert_logging_enabled     = var.enable_alert_logging
    flow_logging_enabled      = var.enable_flow_logging
    s3_logging_enabled        = var.enable_s3_logging
    domain_filtering_enabled  = var.enable_domain_filtering
    suricata_ids_enabled      = var.enable_suricata_rules
    cloudwatch_alarms_enabled = var.enable_cloudwatch_alarms
  }
}

# Deployment Information
output "deployment_info" {
  description = "Deployment information for integration with routing"
  value = {
    firewall_endpoints = [
      for az, sync_state in aws_networkfirewall_firewall.main.firewall_status[0].sync_states : {
        availability_zone = az
        endpoint_id       = sync_state.attachment[0].endpoint_id
        subnet_id         = sync_state.attachment[0].subnet_id
      }
    ]
    vpc_id = var.vpc_id
  }
}

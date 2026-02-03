# Networking Environment Outputs

output "transit_gateway_id" {
  description = "ID of the Transit Gateway"
  value       = module.transit_gateway.tgw_id
}

output "transit_gateway_arn" {
  description = "ARN of the Transit Gateway"
  value       = module.transit_gateway.tgw_arn
}

output "network_firewall_arn" {
  description = "ARN of the Network Firewall"
  value       = module.network_firewall.firewall_arn
}

output "network_vpc_id" {
  description = "ID of the network hub VPC"
  value       = module.network_vpc.vpc_id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = module.network_vpc.private_subnet_ids
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = module.network_vpc.public_subnet_ids
}

output "kms_network_key_arn" {
  description = "ARN of the KMS key for network logs"
  value       = module.kms_network.key_arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for network alerts"
  value       = module.cloudwatch.sns_topic_arn
}

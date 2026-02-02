# DNS Route53 Resolver Module Variables

variable "resolver_name" {
  description = "Name prefix for DNS resolver resources"
  type        = string
  default     = "uk-landing-zone-dns"
}

# Inbound Endpoint
variable "create_inbound_endpoint" {
  description = "Create inbound resolver endpoint"
  type        = bool
  default     = false
}

variable "inbound_subnet_ids" {
  description = "Subnet IDs for inbound endpoint (minimum 2)"
  type        = list(string)
  default     = []
}

variable "inbound_security_group_ids" {
  description = "Security group IDs for inbound endpoint"
  type        = list(string)
  default     = []
}

# Outbound Endpoint
variable "create_outbound_endpoint" {
  description = "Create outbound resolver endpoint"
  type        = bool
  default     = false
}

variable "outbound_subnet_ids" {
  description = "Subnet IDs for outbound endpoint (minimum 2)"
  type        = list(string)
  default     = []
}

variable "outbound_security_group_ids" {
  description = "Security group IDs for outbound endpoint"
  type        = list(string)
  default     = []
}

# Forwarding Rules
variable "forwarding_rules" {
  description = "Map of DNS forwarding rules"
  type = map(object({
    domain_name = string
    target_ips = list(object({
      ip   = string
      port = number
    }))
  }))
  default = {}
}

# Resolver Rule Associations
variable "resolver_rule_associations" {
  description = "Map of resolver rule associations to VPCs"
  type = map(object({
    resolver_rule_id    = string
    forwarding_rule_key = string
    vpc_id              = string
  }))
  default = {}
}

# Private Hosted Zones
variable "private_zones" {
  description = "Map of private hosted zones to create"
  type = map(object({
    domain_name = string
    vpc_associations = list(object({
      vpc_id     = string
      vpc_region = string
    }))
  }))
  default = {}
}

# Cross-Account Zone Associations
variable "cross_account_zone_associations" {
  description = "Map of cross-account zone associations"
  type = map(object({
    zone_id          = string
    private_zone_key = string
    vpc_id           = string
  }))
  default = {}
}

# Query Logging
variable "enable_query_logging" {
  description = "Enable DNS query logging"
  type        = bool
  default     = true
}

variable "query_log_destination_type" {
  description = "Destination type for query logs (cloudwatch or s3)"
  type        = string
  default     = "cloudwatch"
}

variable "query_log_destination_arn" {
  description = "Destination ARN for query logs"
  type        = string
  default     = null
}

variable "query_log_vpc_associations" {
  description = "Map of VPC IDs to associate with query logging"
  type        = map(string)
  default     = {}
}

variable "query_log_retention_days" {
  description = "Retention period for query logs in days"
  type        = number
  default     = 2555 # 7 years
}

variable "query_log_kms_key_id" {
  description = "KMS key ID for encrypting query logs"
  type        = string
  default     = null
}

# DNS Firewall
variable "enable_dns_firewall" {
  description = "Enable Route53 DNS Firewall"
  type        = bool
  default     = false
}

variable "dns_firewall_rules" {
  description = "Map of DNS firewall rules"
  type = map(object({
    domain_list_id          = string
    priority                = number
    action                  = string
    block_response          = string
    block_override_domain   = string
    block_override_dns_type = string
    block_override_ttl      = number
  }))
  default = {}
}

variable "dns_firewall_vpc_associations" {
  description = "Map of DNS firewall VPC associations"
  type = map(object({
    vpc_id              = string
    priority            = number
    mutation_protection = string
  }))
  default = {}
}

# Monitoring
variable "enable_dns_monitoring" {
  description = "Enable CloudWatch monitoring for DNS"
  type        = bool
  default     = true
}

variable "query_volume_threshold" {
  description = "Threshold for DNS query volume alarm"
  type        = number
  default     = 100000
}

variable "alarm_sns_topic_arns" {
  description = "SNS topic ARNs for alarm notifications"
  type        = list(string)
  default     = []
}

# Common Tags
variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

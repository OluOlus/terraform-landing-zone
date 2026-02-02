# AWS Network Firewall Module Variables
# Variables for UK traffic inspection and threat detection

# Core Firewall Variables
variable "firewall_name" {
  description = "Name of the Network Firewall"
  type        = string
  default     = "uk-landing-zone-firewall"
}

variable "firewall_policy_name" {
  description = "Name of the firewall policy"
  type        = string
  default     = "uk-landing-zone-firewall-policy"
}

variable "vpc_id" {
  description = "VPC ID where the firewall will be deployed"
  type        = string
}

variable "subnet_mappings" {
  description = "List of subnet IDs for firewall endpoints"
  type        = list(string)
}

# Firewall Protection Variables
variable "delete_protection" {
  description = "Enable deletion protection for the firewall"
  type        = bool
  default     = true
}

variable "subnet_change_protection" {
  description = "Enable subnet change protection"
  type        = bool
  default     = true
}

variable "firewall_policy_change_protection" {
  description = "Enable firewall policy change protection"
  type        = bool
  default     = true
}

# Firewall Policy Configuration
variable "stateless_default_actions" {
  description = "Default actions for stateless rules"
  type        = list(string)
  default     = ["aws:forward_to_sfe"]
}

variable "stateless_fragment_default_actions" {
  description = "Default actions for fragmented packets"
  type        = list(string)
  default     = ["aws:forward_to_sfe"]
}

variable "stateful_rule_order" {
  description = "Order for stateful rule evaluation (STRICT_ORDER or DEFAULT_ACTION_ORDER)"
  type        = string
  default     = "STRICT_ORDER"
  validation {
    condition     = contains(["STRICT_ORDER", "DEFAULT_ACTION_ORDER"], var.stateful_rule_order)
    error_message = "Must be STRICT_ORDER or DEFAULT_ACTION_ORDER."
  }
}

# Rule Group References
variable "stateless_rule_group_references" {
  description = "List of stateless rule group references"
  type = list(object({
    priority     = number
    resource_arn = string
  }))
  default = []
}

variable "stateful_rule_group_references" {
  description = "List of stateful rule group references"
  type = list(object({
    resource_arn    = string
    priority        = number
    override_action = string
  }))
  default = []
}

# TLS Inspection
variable "tls_inspection_configuration_arn" {
  description = "ARN of TLS inspection configuration"
  type        = string
  default     = null
}

# UK Stateless Rules
variable "create_uk_stateless_rules" {
  description = "Create region-specific stateless rules"
  type        = bool
  default     = true
}

variable "uk_stateless_rules_capacity" {
  description = "Capacity for UK stateless rules"
  type        = number
  default     = 100
}

variable "uk_stateless_rules" {
  description = "region-specific stateless rules configuration"
  type = list(object({
    priority          = number
    actions           = list(string)
    source_cidrs      = string
    destination_cidrs = string
    protocols         = list(number)
    source_ports = list(object({
      from_port = number
      to_port   = number
    }))
    destination_ports = list(object({
      from_port = number
      to_port   = number
    }))
  }))
  default = []
}

# Domain Filtering
variable "enable_domain_filtering" {
  description = "Enable domain-based filtering"
  type        = bool
  default     = true
}

variable "domain_filtering_capacity" {
  description = "Capacity for domain filtering rule group"
  type        = number
  default     = 1000
}

variable "blocked_domains" {
  description = "List of domains to block"
  type        = list(string)
  default = [
    ".malware-domain.com",
    ".phishing-site.net",
    ".known-bad-actor.org"
  ]
}

# Suricata IDS/IPS Rules
variable "enable_suricata_rules" {
  description = "Enable Suricata IDS/IPS rules"
  type        = bool
  default     = true
}

variable "suricata_rules_capacity" {
  description = "Capacity for Suricata rules"
  type        = number
  default     = 10000
}

variable "suricata_rules_string" {
  description = "Suricata rules in string format"
  type        = string
  default     = <<-EOT
    # region-specific IDS/IPS rules
    drop ip any any -> any any (msg:"Block all outbound to known malicious IPs"; sid:1000001; rev:1;)
    alert tcp any any -> any 22 (msg:"SSH connection attempt"; sid:1000002; rev:1;)
    alert tcp any any -> any 3389 (msg:"RDP connection attempt"; sid:1000003; rev:1;)
    drop icmp any any -> any any (msg:"Block ICMP ping sweeps"; itype:8; sid:1000004; rev:1;)
  EOT
}

# Stateful 5-Tuple Rules
variable "enable_stateful_5tuple_rules" {
  description = "Enable stateful 5-tuple rules"
  type        = bool
  default     = false
}

variable "stateful_5tuple_capacity" {
  description = "Capacity for stateful 5-tuple rules"
  type        = number
  default     = 100
}

variable "stateful_5tuple_rules" {
  description = "Stateful 5-tuple rules configuration"
  type = list(object({
    action           = string
    destination      = string
    destination_port = string
    direction        = string
    protocol         = string
    source           = string
    source_port      = string
    sid              = string
  }))
  default = []
}

# Logging Configuration
variable "enable_alert_logging" {
  description = "Enable alert logging to CloudWatch"
  type        = bool
  default     = true
}

variable "enable_flow_logging" {
  description = "Enable flow logging to CloudWatch"
  type        = bool
  default     = true
}

variable "enable_s3_logging" {
  description = "Enable logging to S3"
  type        = bool
  default     = false
}

variable "s3_logging_bucket_name" {
  description = "S3 bucket name for logs"
  type        = string
  default     = null
}

variable "s3_logging_prefix" {
  description = "S3 prefix for logs"
  type        = string
  default     = "network-firewall-logs"
}

variable "s3_log_type" {
  description = "Type of logs to send to S3 (ALERT or FLOW)"
  type        = string
  default     = "ALERT"
  validation {
    condition     = contains(["ALERT", "FLOW"], var.s3_log_type)
    error_message = "Must be ALERT or FLOW."
  }
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 2555 # 7 years for compliance
  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 2192, 2555, 2922, 3288, 3653], var.log_retention_days)
    error_message = "Must be a valid CloudWatch Logs retention period."
  }
}

variable "log_kms_key_id" {
  description = "KMS key ID for encrypting logs"
  type        = string
  default     = null
}

# Routing Configuration
variable "create_firewall_routes" {
  description = "Create route tables for firewall subnets"
  type        = bool
  default     = false
}

# CloudWatch Alarms
variable "enable_cloudwatch_alarms" {
  description = "Enable CloudWatch alarms for firewall monitoring"
  type        = bool
  default     = true
}

variable "packet_drop_threshold" {
  description = "Threshold for packet drop alarm"
  type        = number
  default     = 1000
}

variable "rule_evaluation_failure_threshold" {
  description = "Threshold for rule evaluation failure alarm"
  type        = number
  default     = 100
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

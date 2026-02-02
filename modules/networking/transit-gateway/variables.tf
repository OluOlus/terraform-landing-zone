# Transit Gateway Module Variables
# Variables for UK hub-and-spoke network architecture

# Core Transit Gateway Variables
variable "tgw_name" {
  description = "Name of the Transit Gateway"
  type        = string
  default     = "uk-landing-zone-tgw"
}

variable "tgw_description" {
  description = "Description of the Transit Gateway"
  type        = string
  default     = "UK Landing Zone centralized network hub"
}

variable "amazon_side_asn" {
  description = "Private Autonomous System Number (ASN) for the Amazon side of the BGP session"
  type        = number
  default     = 64512
  validation {
    condition     = var.amazon_side_asn >= 64512 && var.amazon_side_asn <= 65534
    error_message = "ASN must be in the private range 64512-65534."
  }
}

variable "default_route_table_association" {
  description = "Enable default route table association"
  type        = string
  default     = "disable"
  validation {
    condition     = contains(["enable", "disable"], var.default_route_table_association)
    error_message = "Must be 'enable' or 'disable'."
  }
}

variable "default_route_table_propagation" {
  description = "Enable default route table propagation"
  type        = string
  default     = "disable"
  validation {
    condition     = contains(["enable", "disable"], var.default_route_table_propagation)
    error_message = "Must be 'enable' or 'disable'."
  }
}

variable "vpn_ecmp_support" {
  description = "Enable VPN ECMP (Equal Cost Multi-Path) support"
  type        = string
  default     = "enable"
  validation {
    condition     = contains(["enable", "disable"], var.vpn_ecmp_support)
    error_message = "Must be 'enable' or 'disable'."
  }
}

variable "auto_accept_shared_attachments" {
  description = "Automatically accept cross-account attachments"
  type        = string
  default     = "enable"
  validation {
    condition     = contains(["enable", "disable"], var.auto_accept_shared_attachments)
    error_message = "Must be 'enable' or 'disable'."
  }
}

# VPC Attachments
variable "vpc_attachments" {
  description = "Map of VPC attachments to create"
  type = map(object({
    vpc_id                          = string
    subnet_ids                      = list(string)
    appliance_mode_support          = string
    default_route_table_association = bool
    default_route_table_propagation = bool
    environment                     = string
  }))
  default = {}
}

# Route Table Configuration
variable "create_production_route_table" {
  description = "Create a dedicated route table for production workloads"
  type        = bool
  default     = true
}

variable "create_non_production_route_table" {
  description = "Create a dedicated route table for non-production workloads"
  type        = bool
  default     = true
}

variable "create_shared_services_route_table" {
  description = "Create a dedicated route table for shared services"
  type        = bool
  default     = true
}

variable "create_sandbox_route_table" {
  description = "Create an isolated route table for sandbox environments"
  type        = bool
  default     = true
}

variable "route_table_associations" {
  description = "Map of route table associations"
  type = map(object({
    vpc_attachment_key = string
    route_table_name   = string
  }))
  default = {}
}

variable "route_table_propagations" {
  description = "Map of route table propagations"
  type = map(object({
    vpc_attachment_key = string
    route_table_name   = string
  }))
  default = {}
}

variable "static_routes" {
  description = "Map of static routes to create"
  type = map(object({
    destination_cidr_block = string
    route_table_name       = string
    vpc_attachment_key     = string
    attachment_id          = string
    blackhole              = bool
  }))
  default = {}
}

# VPN Configuration
variable "enable_vpn_attachment" {
  description = "Enable VPN attachment for on-premises connectivity"
  type        = bool
  default     = false
}

variable "customer_gateway_id" {
  description = "Customer Gateway ID for VPN connection"
  type        = string
  default     = null
}

variable "vpn_static_routes_only" {
  description = "Use static routes for VPN (instead of BGP)"
  type        = bool
  default     = false
}

variable "vpn_tunnel1_inside_cidr" {
  description = "Inside CIDR for VPN tunnel 1"
  type        = string
  default     = null
}

variable "vpn_tunnel1_preshared_key" {
  description = "Pre-shared key for VPN tunnel 1"
  type        = string
  default     = null
  sensitive   = true
}

variable "vpn_tunnel2_inside_cidr" {
  description = "Inside CIDR for VPN tunnel 2"
  type        = string
  default     = null
}

variable "vpn_tunnel2_preshared_key" {
  description = "Pre-shared key for VPN tunnel 2"
  type        = string
  default     = null
  sensitive   = true
}

# Resource Access Manager (RAM) Configuration
variable "enable_ram_share" {
  description = "Enable RAM sharing for cross-account access"
  type        = bool
  default     = true
}

variable "ram_principal_associations" {
  description = "List of principals (account IDs or OU ARNs) to share Transit Gateway with"
  type        = list(string)
  default     = []
}

# Flow Logs Configuration
variable "enable_flow_logs" {
  description = "Enable Transit Gateway flow logs"
  type        = bool
  default     = true
}

variable "flow_logs_destination_type" {
  description = "Type of flow logs destination (cloud-watch-logs or s3)"
  type        = string
  default     = "cloud-watch-logs"
  validation {
    condition     = contains(["cloud-watch-logs", "s3"], var.flow_logs_destination_type)
    error_message = "Must be 'cloud-watch-logs' or 's3'."
  }
}

variable "flow_logs_destination_arn" {
  description = "ARN of the flow logs destination (S3 bucket or CloudWatch log group)"
  type        = string
  default     = null
}

variable "flow_logs_retention_days" {
  description = "Retention period for flow logs in days"
  type        = number
  default     = 2555 # 7 years for compliance
  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 2192, 2555, 2922, 3288, 3653], var.flow_logs_retention_days)
    error_message = "Must be a valid CloudWatch Logs retention period."
  }
}

variable "flow_logs_kms_key_id" {
  description = "KMS key ID for encrypting flow logs"
  type        = string
  default     = null
}

# Network Manager Configuration
variable "enable_network_manager" {
  description = "Enable AWS Network Manager for monitoring and visualization"
  type        = bool
  default     = false
}

# Common Tags
variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

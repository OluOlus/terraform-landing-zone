# Networking Environment Variables

variable "owner_email" {
  description = "Email address of the infrastructure owner"
  type        = string
}

variable "network_team_email" {
  description = "Email address for network team notifications"
  type        = string
}

variable "network_hub_cidr" {
  description = "CIDR block for the network hub VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.11.0/24", "10.0.12.0/24", "10.0.13.0/24"]
}

variable "database_subnet_cidrs" {
  description = "CIDR blocks for database subnets"
  type        = list(string)
  default     = ["10.0.21.0/24", "10.0.22.0/24", "10.0.23.0/24"]
}

variable "private_hosted_zone_name" {
  description = "Name of the private hosted zone"
  type        = string
  default     = "uk-landing-zone.internal"
}

variable "enable_dns_resolver_endpoints" {
  description = "Enable DNS resolver endpoints for hybrid DNS"
  type        = bool
  default     = false
}

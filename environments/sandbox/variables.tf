# Sandbox Environment Variables

variable "owner_email" {
  description = "Email address of the infrastructure owner"
  type        = string
}

variable "sandbox_team_email" {
  description = "Email address for sandbox team notifications"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the sandbox VPC"
  type        = string
  default     = "10.20.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.20.1.0/24", "10.20.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.20.11.0/24", "10.20.12.0/24"]
}

variable "database_subnet_cidrs" {
  description = "CIDR blocks for database subnets"
  type        = list(string)
  default     = ["10.20.21.0/24", "10.20.22.0/24"]
}

variable "monthly_budget_limit" {
  description = "Monthly budget limit in USD for sandbox (strict limit)"
  type        = string
  default     = "500"
}

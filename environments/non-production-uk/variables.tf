# Non-Production UK Environment Variables

variable "owner_email" {
  description = "Email address of the infrastructure owner"
  type        = string
}

variable "dev_team_email" {
  description = "Email address for development team notifications"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the non-production VPC"
  type        = string
  default     = "10.10.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.10.1.0/24", "10.10.2.0/24", "10.10.3.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.10.11.0/24", "10.10.12.0/24", "10.10.13.0/24"]
}

variable "database_subnet_cidrs" {
  description = "CIDR blocks for database subnets"
  type        = list(string)
  default     = ["10.10.21.0/24", "10.10.22.0/24", "10.10.23.0/24"]
}

variable "config_s3_bucket_name" {
  description = "S3 bucket name for AWS Config delivery"
  type        = string
}

variable "monthly_budget_limit" {
  description = "Monthly budget limit in USD for non-production"
  type        = string
  default     = "2000"
}

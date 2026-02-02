# Management Environment Variables

variable "organization_name" {
  description = "Name of the AWS Organization"
  type        = string
  default     = "UK Secure Landing Zone"
}

variable "owner_email" {
  description = "Email address of the infrastructure owner"
  type        = string
}

variable "ops_team_email" {
  description = "Email address for operations team notifications"
  type        = string
}

variable "monthly_budget_limit" {
  description = "Monthly budget limit in USD"
  type        = string
  default     = "10000"
}

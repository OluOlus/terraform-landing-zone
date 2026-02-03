# Security Environment Variables

variable "owner_email" {
  description = "Email address of the infrastructure owner"
  type        = string
}

variable "security_team_email" {
  description = "Email address for security team notifications"
  type        = string
}

variable "config_s3_bucket_name" {
  description = "S3 bucket name for AWS Config delivery"
  type        = string
}

variable "enable_auto_remediation" {
  description = "Enable automatic remediation of security findings"
  type        = bool
  default     = false # Default to false for safety, enable explicitly
}

variable "delegated_admin_account_id" {
  description = "Account ID for delegated administrator (if different from current)"
  type        = string
  default     = null
}

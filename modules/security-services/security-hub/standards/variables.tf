# Variables for Security Hub Standards Module

variable "aws_region" {
  description = "AWS region for Security Hub standards deployment"
  type        = string
  default     = "us-east-1"
}

variable "common_tags" {
  description = "Common tags to apply to all standards resources"
  type        = map(string)
  default     = {}
}

variable "security_hub_account_dependency" {
  description = "Dependency reference for Security Hub account creation"
  type        = any
  default     = null
}

variable "enable_cis_standard" {
  description = "Enable CIS AWS Foundations Benchmark standard"
  type        = bool
  default     = true
}

variable "enable_ncsc_insights" {
  description = "Enable Security Standards-specific insights and monitoring"
  type        = bool
  default     = true
}

variable "enable_cis_insights" {
  description = "Enable CIS-specific insights and monitoring"
  type        = bool
  default     = true
}

variable "enable_aws_foundational_insights" {
  description = "Enable AWS Foundational Security insights and monitoring"
  type        = bool
  default     = true
}
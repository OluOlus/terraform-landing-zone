# Variables for Security Hub Standards Module

variable "aws_region" {
  description = "AWS region for Security Hub standards deployment"
  type        = string
  default     = "eu-west-2"
  validation {
    condition     = contains(["eu-west-2", "eu-west-1"], var.aws_region)
    error_message = "AWS region must be a UK region (eu-west-2 or eu-west-1) for UK data residency compliance."
  }
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
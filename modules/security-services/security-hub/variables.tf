variable "aws_region" {
  description = "AWS region for Security Hub deployment"
  type        = string
  default     = "eu-west-2"

  validation {
    condition     = contains(["eu-west-2", "eu-west-1"], var.aws_region)
    error_message = "AWS region must be a UK region (eu-west-2 or eu-west-1) for UK data residency compliance."
  }
}

variable "is_delegated_admin" {
  description = "Whether this account is the delegated Security Hub admin account"
  type        = bool
  default     = false
}

variable "admin_account_id" {
  description = "AWS account ID for the Security Hub admin account"
  type        = string
  default     = null

  validation {
    condition     = var.admin_account_id == null || can(regex("^[0-9]{12}$", var.admin_account_id))
    error_message = "Admin account ID must be a valid 12-digit AWS account ID."
  }
}

variable "enable_cis_standard" {
  description = "Enable CIS AWS Foundations Benchmark standard"
  type        = bool
  default     = true
}

variable "enable_default_standards" {
  description = "Enable default Security Hub standards on account creation"
  type        = bool
  default     = true
}

variable "auto_enable_new_accounts" {
  description = "Automatically enable Security Hub for new organization accounts"
  type        = bool
  default     = true
}

variable "auto_enable_standards" {
  description = "Automatically enable standards for new organization accounts"
  type        = string
  default     = "DEFAULT"

  validation {
    condition     = contains(["DEFAULT", "NONE"], var.auto_enable_standards)
    error_message = "Auto enable standards must be either 'DEFAULT' or 'NONE'."
  }
}

variable "enable_finding_aggregation" {
  description = "Enable cross-region finding aggregation"
  type        = bool
  default     = true
}

variable "finding_aggregation_linking_mode" {
  description = "Linking mode for finding aggregation"
  type        = string
  default     = "SPECIFIED_REGIONS"

  validation {
    condition     = contains(["ALL_REGIONS", "ALL_REGIONS_EXCEPT_SPECIFIED", "SPECIFIED_REGIONS"], var.finding_aggregation_linking_mode)
    error_message = "Finding aggregation linking mode must be one of: ALL_REGIONS, ALL_REGIONS_EXCEPT_SPECIFIED, SPECIFIED_REGIONS."
  }
}

variable "finding_aggregation_regions" {
  description = "List of regions for finding aggregation (when using SPECIFIED_REGIONS mode)"
  type        = list(string)
  default     = ["eu-west-2", "eu-west-1"]

  validation {
    condition     = alltrue([for region in var.finding_aggregation_regions : contains(["eu-west-2", "eu-west-1"], region)])
    error_message = "Finding aggregation regions must only include UK regions (eu-west-2, eu-west-1) for UK data residency compliance."
  }
}

variable "security_hub_account_dependency" {
  description = "Dependency reference for Security Hub account creation"
  type        = any
  default     = null
}

variable "common_tags" {
  description = "Common tags to apply to all Security Hub resources"
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      contains(keys(var.common_tags), "DataClassification"),
      contains(keys(var.common_tags), "Environment"),
      contains(keys(var.common_tags), "CostCenter")
    ])
    error_message = "Common tags must include mandatory UK tags: DataClassification, Environment, and CostCenter."
  }
}

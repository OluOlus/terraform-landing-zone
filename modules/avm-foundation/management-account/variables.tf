# Variables for Management Account Module

variable "management_account_name" {
  description = "Name of the management account"
  type        = string
  default     = "UK-Landing-Zone-Management"
}

variable "management_account_email" {
  description = "Email address for the management account"
  type        = string
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.management_account_email))
    error_message = "Management account email must be a valid email address."
  }
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Project             = "UK-Landing-Zone"
    ManagedBy           = "Terraform"
    DataClassification  = "Internal"
    Environment         = "Management"
    CostCenter          = "Platform"
    Owner               = "Platform-Team"
    ComplianceFramework = "Security Standards-UK-GDPR"
    DataResidency       = "UK"
  }
}

variable "aws_regions" {
  description = "List of allowed AWS regions for UK data residency"
  type        = list(string)
  default     = ["us-west-2", "us-east-1"]
  validation {
    condition = alltrue([
      for region in var.aws_regions : contains(["us-west-2", "us-east-1"], region)
    ])
    error_message = "Only specified regions (us-west-2, us-east-1) are allowed for data residency compliance."
  }
}

variable "enable_consolidated_billing" {
  description = "Enable consolidated billing for the organization"
  type        = bool
  default     = true
}

variable "config_delivery_frequency" {
  description = "Frequency for Config delivery channel"
  type        = string
  default     = "TwentyFour_Hours"
  validation {
    condition = contains([
      "One_Hour", "Three_Hours", "Six_Hours", "Twelve_Hours", "TwentyFour_Hours"
    ], var.config_delivery_frequency)
    error_message = "Config delivery frequency must be a valid AWS Config delivery frequency."
  }
}

variable "force_destroy_buckets" {
  description = "Force destroy S3 buckets even if they contain objects (use with caution)"
  type        = bool
  default     = false
}

variable "enable_service_access_principals" {
  description = "List of additional AWS service access principals to enable"
  type        = list(string)
  default     = []
}

variable "organizational_units" {
  description = "Configuration for organizational units"
  type = map(object({
    name        = string
    description = optional(string, "")
  }))
  default = {
    production_uk = {
      name        = "Production-UK"
      description = "Production workloads in specified regions"
    }
    non_production_uk = {
      name        = "Non-Production-UK"
      description = "Development and testing workloads in specified regions"
    }
    sandbox = {
      name        = "Sandbox"
      description = "Sandbox environment for experimentation"
    }
  }
}
# Variables for Organization Structure Module

variable "common_tags" {
  description = "Common tags to be applied to all resources"
  type        = map(string)
  default = {
    Project             = "UK-AWS-Secure-Landing-Zone"
    ManagedBy           = "Terraform"
    ComplianceFramework = "Security Standards-Cloud-Security-Principles"
    DataResidency       = "UK"
  }
}

variable "enable_service_control_policies" {
  description = "Whether to enable and attach service control policies"
  type        = bool
  default     = true
}

variable "policy_path" {
  description = "Path to the directory containing SCP policy JSON files"
  type        = string
  default     = "../../policies/scps"
}

variable "organizational_units" {
  description = "Configuration for organizational units"
  type = map(object({
    name                = string
    environment         = string
    data_classification = string
    purpose             = string
  }))
  default = {
    production_uk = {
      name                = "Production-UK"
      environment         = "production"
      data_classification = "confidential"
      purpose             = "Production workloads for UK operations"
    }
    non_production_uk = {
      name                = "Non-Production-UK"
      environment         = "non-production"
      data_classification = "internal"
      purpose             = "Development and testing environments for UK operations"
    }
    sandbox = {
      name                = "Sandbox"
      environment         = "sandbox"
      data_classification = "internal"
      purpose             = "Experimentation and proof-of-concept environments"
    }
    core_infrastructure = {
      name                = "Core-Infrastructure"
      environment         = "infrastructure"
      data_classification = "restricted"
      purpose             = "Core infrastructure accounts (Security, Logging, Networking)"
    }
  }
}
# AWS Config Module Variables
# Variables for compliance monitoring with Security Standards, GDPR, and Security Essentials frameworks

# Core Config Service Variables
variable "enable_config_recorder" {
  description = "Enable AWS Config recorder"
  type        = bool
  default     = true
}

variable "config_recorder_name" {
  description = "Name of the Config recorder"
  type        = string
  default     = "uk-compliance-recorder"
}

variable "config_service_role_arn" {
  description = "ARN of the IAM role for Config service"
  type        = string
}

variable "record_all_supported" {
  description = "Record all supported resource types"
  type        = bool
  default     = true
}

variable "include_global_resources" {
  description = "Include global resources in recording"
  type        = bool
  default     = true
}

variable "recording_frequency" {
  description = "Recording frequency for Config"
  type        = string
  default     = "CONTINUOUS"
  validation {
    condition     = contains(["CONTINUOUS", "DAILY"], var.recording_frequency)
    error_message = "Recording frequency must be CONTINUOUS or DAILY."
  }
}

# Delivery Channel Variables
variable "delivery_channel_name" {
  description = "Name of the Config delivery channel"
  type        = string
  default     = "uk-compliance-delivery-channel"
}

variable "config_s3_bucket_name" {
  description = "S3 bucket name for Config delivery"
  type        = string
}

variable "config_s3_key_prefix" {
  description = "S3 key prefix for Config delivery"
  type        = string
  default     = "config"
}

variable "snapshot_delivery_frequency" {
  description = "Frequency for Config snapshot delivery"
  type        = string
  default     = "TwentyFour_Hours"
  validation {
    condition = contains([
      "One_Hour", "Three_Hours", "Six_Hours", "Twelve_Hours", "TwentyFour_Hours"
    ], var.snapshot_delivery_frequency)
    error_message = "Invalid snapshot delivery frequency."
  }
}

# Organization Aggregator Variables
variable "aggregator_name" {
  description = "Name of the Config aggregator"
  type        = string
  default     = "uk-organization-aggregator"
}

variable "is_delegated_admin" {
  description = "Is this the delegated admin account"
  type        = bool
  default     = false
}

variable "organization_role_arn" {
  description = "Organization role ARN for aggregator"
  type        = string
  default     = null
}

# Security Standards Conformance Pack Variables
variable "enable_ncsc_pack" {
  description = "Enable Security Standards conformance pack"
  type        = bool
  default     = true
}

variable "ncsc_access_key_max_age" {
  description = "Maximum age in days for access keys (Security Standards)"
  type        = string
  default     = "90"
}

variable "ncsc_kms_key_id" {
  description = "KMS Key ID for Security Standards encryption requirements"
  type        = string
  default     = ""
}

variable "ncsc_root_credential_max_age" {
  description = "Maximum age for root user credentials (Security Standards)"
  type        = string
  default     = "90"
}

variable "ncsc_approved_ami_ids" {
  description = "List of approved AMI IDs for Security Standards compliance"
  type        = list(string)
  default     = []
}

# GDPR Conformance Pack Variables
variable "enable_gdpr_pack" {
  description = "Enable GDPR conformance pack"
  type        = bool
  default     = true
}

variable "gdpr_data_retention_days" {
  description = "Data retention period in days for GDPR compliance"
  type        = string
  default     = "2555" # 7 years
}

variable "gdpr_key_rotation_days" {
  description = "Key rotation period in days for GDPR compliance"
  type        = string
  default     = "365"
}

variable "gdpr_access_log_retention_days" {
  description = "Access log retention period in days for GDPR compliance"
  type        = string
  default     = "2555" # 7 years
}

variable "gdpr_encryption_key_ids" {
  description = "List of encryption key IDs for GDPR compliance"
  type        = string
  default     = ""
}

# Security Essentials Conformance Pack Variables
variable "enable_cyber_essentials_pack" {
  description = "Enable Security Essentials conformance pack"
  type        = bool
  default     = true
}

variable "ce_firewall_timeout_seconds" {
  description = "Firewall timeout in seconds for Security Essentials"
  type        = string
  default     = "300"
}

variable "ce_patch_compliance_timeout_days" {
  description = "Patch compliance timeout in days for Security Essentials"
  type        = string
  default     = "30"
}

variable "ce_password_min_length" {
  description = "Minimum password length for Security Essentials"
  type        = string
  default     = "14"
}

variable "ce_encryption_key_ids" {
  description = "List of encryption key IDs for Security Essentials compliance"
  type        = string
  default     = ""
}

# UK-Specific Custom Rules Variables
variable "enable_uk_data_residency_rule" {
  description = "Enable UK data residency enforcement rule"
  type        = bool
  default     = true
}

variable "uk_approved_ami_ids" {
  description = "List of UK-approved AMI IDs"
  type        = list(string)
  default     = []
}

variable "enable_uk_mandatory_tagging_rule" {
  description = "Enable UK mandatory tagging rule"
  type        = bool
  default     = true
}

variable "uk_mandatory_tagging_resource_types" {
  description = "Resource types for UK mandatory tagging rule"
  type        = list(string)
  default = [
    "AWS::EC2::Instance",
    "AWS::S3::Bucket",
    "AWS::RDS::DBInstance",
    "AWS::ElasticLoadBalancing::LoadBalancer",
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "AWS::DynamoDB::Table",
    "AWS::EFS::FileSystem"
  ]
}

# Legacy Variables (for backward compatibility)
variable "config_recorder_id" {
  description = "Config recorder ID dependency (legacy)"
  type        = string
  default     = null
}

# Common Variables
variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

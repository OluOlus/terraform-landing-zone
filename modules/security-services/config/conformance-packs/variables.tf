# Conformance Packs Module Variables
# Variables for all compliance framework conformance packs

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

# Common Variables
variable "config_recorder_dependency" {
  description = "Config recorder dependency for proper resource ordering"
  type        = string
  default     = null
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}
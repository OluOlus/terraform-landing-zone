# AWS Backup Module Variables

variable "vault_name" {
  description = "Name of the backup vault"
  type        = string
  default     = "uk-landing-zone-backup-vault"
}

variable "vault_kms_key_arn" {
  description = "KMS key ARN for backup vault encryption"
  type        = string
}

variable "vault_policy" {
  description = "Backup vault policy JSON"
  type        = string
  default     = null
}

variable "backup_plans" {
  description = "Map of backup plans to create"
  type = map(object({
    rules = list(object({
      rule_name           = string
      schedule            = string
      start_window        = number
      completion_window   = number
      recovery_point_tags = map(string)
      lifecycle = object({
        cold_storage_after = number
        delete_after       = number
      })
      copy_actions = list(object({
        destination_vault_arn = string
        lifecycle = object({
          cold_storage_after = number
          delete_after       = number
        })
      }))
    }))
  }))
  default = {}
}

variable "backup_selections" {
  description = "Map of backup selections"
  type = map(object({
    plan_name    = string
    iam_role_arn = string
    resources    = list(string)
    selection_tags = list(object({
      key   = string
      value = string
    }))
  }))
  default = {}
}

variable "create_secondary_vault" {
  description = "Create secondary backup vault for DR"
  type        = bool
  default     = true
}

variable "secondary_vault_region" {
  description = "Region for secondary backup vault"
  type        = string
  default     = "us-west-2"
}

variable "secondary_vault_kms_key_arn" {
  description = "KMS key ARN for secondary vault encryption"
  type        = string
  default     = null
}

variable "create_backup_framework" {
  description = "Create backup compliance framework"
  type        = bool
  default     = false
}

variable "framework_name" {
  description = "Name of the backup framework"
  type        = string
  default     = "uk-landing-zone-backup-framework"
}

variable "framework_controls" {
  description = "List of framework controls"
  type = list(object({
    name = string
    input_parameters = list(object({
      name  = string
      value = string
    }))
    scope = object({
      compliance_resource_ids   = list(string)
      compliance_resource_types = list(string)
      tags                      = map(string)
    })
  }))
  default = []
}

variable "create_report_plan" {
  description = "Create backup report plan"
  type        = bool
  default     = false
}

variable "report_plan_name" {
  description = "Name of the report plan"
  type        = string
  default     = "uk-landing-zone-backup-report"
}

variable "report_formats" {
  description = "List of report formats"
  type        = list(string)
  default     = ["CSV", "JSON"]
}

variable "report_s3_bucket_name" {
  description = "S3 bucket for backup reports"
  type        = string
  default     = null
}

variable "report_s3_key_prefix" {
  description = "S3 key prefix for backup reports"
  type        = string
  default     = "backup-reports/"
}

variable "report_template" {
  description = "Report template name"
  type        = string
  default     = "BACKUP_JOB_REPORT"
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

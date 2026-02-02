variable "kms_key_arn" {
  description = "KMS key ARN for encryption"
  type        = string
}

variable "remediation_bucket_name" {
  description = "S3 bucket name for remediation artifacts"
  type        = string
}

variable "remediation_bucket_arn" {
  description = "S3 bucket ARN for remediation artifacts"
  type        = string
  default     = ""
}

variable "sns_topic_arn" {
  description = "SNS topic ARN for notifications"
  type        = string
}

variable "cloudwatch_log_group_name" {
  description = "CloudWatch log group name"
  type        = string
}

variable "enable_s3_public_access_remediation" {
  description = "Enable S3 public access remediation"
  type        = bool
  default     = true
}

variable "enable_unencrypted_volumes_remediation" {
  description = "Enable unencrypted volumes remediation"
  type        = bool
  default     = true
}

variable "enable_untagged_resources_remediation" {
  description = "Enable untagged resources remediation"
  type        = bool
  default     = true
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 300
}

variable "lambda_memory_size" {
  description = "Lambda function memory size in MB"
  type        = number
  default     = 512
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}
variable "trail_name" {
  description = "Name of the CloudTrail"
  type        = string
}

variable "s3_bucket_name" {
  description = "S3 bucket name for CloudTrail logs"
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key ARN for encryption"
  type        = string
}

variable "is_multi_region_trail" {
  description = "Whether the trail is multi-region"
  type        = bool
  default     = true
}

variable "is_organization_trail" {
  description = "Whether this is an organization trail"
  type        = bool
  default     = true
}

variable "enable_cloudwatch_logs" {
  description = "Enable CloudWatch Logs integration"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 90
}

variable "common_tags" {
  description = "Common tags"
  type        = map(string)
  default     = {}
}

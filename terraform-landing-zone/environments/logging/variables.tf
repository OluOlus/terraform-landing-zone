# Logging Environment Variables

variable "owner_email" {
  description = "Email address of the infrastructure owner"
  type        = string
}

variable "ops_team_email" {
  description = "Email address for operations team notifications"
  type        = string
}

variable "log_archive_bucket_name" {
  description = "Name of the primary log archive S3 bucket"
  type        = string
}

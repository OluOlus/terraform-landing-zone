# Shared Backend Configuration for UK AWS Secure Landing Zone
# This file provides the template for Terraform state management with encryption

terraform {
  backend "s3" {
    # These values will be provided via backend config files or CLI
    # bucket         = "uk-landing-zone-terraform-state-${account_id}"
    # key            = "terraform.tfstate"
    # region         = "us-east-1"
    # dynamodb_table = "uk-landing-zone-terraform-locks"

    # Security and compliance settings
    encrypt = true
    server_side_encryption_configuration {
      rule {
        apply_server_side_encryption_by_default {
          sse_algorithm     = "aws:kms"
          kms_master_key_id = "alias/terraform-state-key"
        }
      }
    }

    # Versioning for state recovery
    versioning = true

    # Access logging for audit trail
    logging {
      target_bucket = "uk-landing-zone-access-logs-${account_id}"
      target_prefix = "terraform-state-access/"
    }

    # Block public access for security
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true

    # Lifecycle configuration for cost optimization
    lifecycle_configuration {
      rule {
        id     = "terraform_state_lifecycle"
        status = "Enabled"

        noncurrent_version_expiration {
          noncurrent_days = 90
        }

        noncurrent_version_transition {
          noncurrent_days = 30
          storage_class   = "STANDARD_IA"
        }

        noncurrent_version_transition {
          noncurrent_days = 60
          storage_class   = "GLACIER"
        }
      }
    }
  }
}

# Backend configuration variables (used in backend config files)
variable "state_bucket_name" {
  description = "Name of the S3 bucket for Terraform state"
  type        = string
  default     = ""
}

variable "state_key" {
  description = "Path to the state file within the S3 bucket"
  type        = string
  default     = "terraform.tfstate"
}

variable "dynamodb_table_name" {
  description = "Name of the DynamoDB table for state locking"
  type        = string
  default     = "uk-landing-zone-terraform-locks"
}

variable "kms_key_id" {
  description = "KMS key ID for state encryption"
  type        = string
  default     = "alias/terraform-state-key"
}

# Local values for backend configuration
locals {
  backend_config = {
    bucket         = var.state_bucket_name
    key            = var.state_key
    region         = var.primary_region
    dynamodb_table = var.dynamodb_table_name
    encrypt        = true
    kms_key_id     = var.kms_key_id
  }
}

# Output backend configuration for reference
output "backend_config" {
  description = "Backend configuration for Terraform state"
  value       = local.backend_config
  sensitive   = false
}
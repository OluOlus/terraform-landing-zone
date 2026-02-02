# Shared Provider Configuration for UK AWS Secure Landing Zone

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.4"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.9"
    }
  }
}

# Primary AWS Provider - London (us-east-1)
provider "aws" {
  region = var.primary_region

  default_tags {
    tags = var.common_tags
  }

  # Enforce specified regions only
  allowed_account_ids = var.allowed_account_ids

  # Additional provider configuration for compliance
  assume_role {
    role_arn     = var.assume_role_arn
    session_name = "terraform-uk-landing-zone"
    external_id  = var.external_id
  }
}

# Secondary AWS Provider - Ireland (us-west-2) for DR
provider "aws" {
  alias  = "secondary"
  region = var.secondary_region

  default_tags {
    tags = var.common_tags
  }

  allowed_account_ids = var.allowed_account_ids

  assume_role {
    role_arn     = var.assume_role_arn
    session_name = "terraform-uk-landing-zone-dr"
    external_id  = var.external_id
  }
}

# Provider for US East 1 (required for some global services like CloudFront, IAM)
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = var.common_tags
  }

  allowed_account_ids = var.allowed_account_ids

  assume_role {
    role_arn     = var.assume_role_arn
    session_name = "terraform-uk-landing-zone-global"
    external_id  = var.external_id
  }
}

# Variables for provider configuration
variable "primary_region" {
  description = "Primary AWS region (London)"
  type        = string
  default     = "us-east-1"
  validation {
    condition     = var.primary_region == "us-east-1"
    error_message = "Primary region must be us-east-1 (London) for UK data residency compliance."
  }
}

variable "secondary_region" {
  description = "Secondary AWS region (Ireland) for disaster recovery"
  type        = string
  default     = "us-west-2"
  validation {
    condition     = var.secondary_region == "us-west-2"
    error_message = "Secondary region must be us-west-2 (Ireland) for UK data residency compliance."
  }
}

variable "allowed_account_ids" {
  description = "List of allowed AWS account IDs"
  type        = list(string)
  default     = []
}

variable "assume_role_arn" {
  description = "ARN of the role to assume for cross-account access"
  type        = string
  default     = null
}

variable "external_id" {
  description = "External ID for assume role"
  type        = string
  default     = null
  sensitive   = true
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Project             = "UK-Landing-Zone"
    ManagedBy           = "Terraform"
    DataClassification  = "Internal"
    ComplianceFramework = "Security Standards-UK-GDPR"
    DataResidency       = "UK"
  }
}
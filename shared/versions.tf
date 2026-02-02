# Version Constraints for UK AWS Secure Landing Zone

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
      configuration_aliases = [
        aws.secondary,
        aws.us_east_1
      ]
    }

    random = {
      source  = "hashicorp/random"
      version = "~> 3.4"
    }

    time = {
      source  = "hashicorp/time"
      version = "~> 0.9"
    }

    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }

    local = {
      source  = "hashicorp/local"
      version = "~> 2.4"
    }

    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }

    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }

    template = {
      source  = "hashicorp/template"
      version = "~> 2.2"
    }
  }
}

# Provider version constraints for AWS Verified Modules compatibility
locals {
  avm_compatible_versions = {
    aws_provider_version    = "~> 5.0"
    terraform_version       = ">= 1.5.0"
    random_provider_version = "~> 3.4"
    time_provider_version   = "~> 0.9"
  }
}

# Version validation
check "terraform_version" {
  assert {
    condition     = can(regex("^1\\.[5-9]\\.", terraform.version))
    error_message = "Terraform version must be 1.5.0 or higher for UK Landing Zone compatibility."
  }
}

# AWS provider version check
data "aws_caller_identity" "current" {}

check "aws_provider_compatibility" {
  assert {
    condition     = data.aws_caller_identity.current.account_id != ""
    error_message = "AWS provider must be properly configured with valid credentials."
  }
}

# Output version information for reference
output "version_info" {
  description = "Version information for the UK Landing Zone"
  value = {
    terraform_version = terraform.version
    provider_versions = local.avm_compatible_versions
    deployment_time   = timestamp()
  }
}
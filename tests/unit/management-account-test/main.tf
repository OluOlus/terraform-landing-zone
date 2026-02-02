# Test configuration for Management Account module

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Use the management account module
module "management_account" {
  source = "../../../modules/avm-foundation/management-account"

  management_account_name  = "UK-Landing-Zone-Test"
  management_account_email = "test@company.com"

  common_tags = {
    Project             = "UK-Landing-Zone-Test"
    ManagedBy           = "Terraform"
    DataClassification  = "Internal"
    Environment         = "Test"
    CostCenter          = "Platform"
    Owner               = "Platform-Team"
    ComplianceFramework = "Security Standards-UK-GDPR"
    DataResidency       = "UK"
  }

  force_destroy_buckets = true
}

# Test outputs
output "organization_id" {
  description = "The ID of the AWS Organization"
  value       = module.management_account.organization_id
}

output "production_uk_ou_id" {
  description = "The ID of the Production UK organizational unit"
  value       = module.management_account.production_uk_ou_id
}

output "uk_data_residency_policy_id" {
  description = "The ID of the UK Data Residency SCP"
  value       = module.management_account.uk_data_residency_policy_id
}

output "config_s3_bucket_name" {
  description = "The name of the S3 bucket for Config"
  value       = module.management_account.config_s3_bucket_name
}
# Security Hub Standards Integration
# This file integrates all compliance framework standards for the UK Landing Zone

# Include all compliance framework standards
module "compliance_standards" {
  source = "./standards"

  # Pass through variables needed by the standards modules
  aws_region                      = var.aws_region
  common_tags                     = var.common_tags
  security_hub_account_dependency = aws_securityhub_account.main
  enable_cis_standard             = var.enable_cis_standard

  # Enable all insights by default for comprehensive monitoring
  enable_ncsc_insights             = true
  enable_cis_insights              = var.enable_cis_standard
  enable_aws_foundational_insights = true

  providers = {
    aws = aws
  }
}
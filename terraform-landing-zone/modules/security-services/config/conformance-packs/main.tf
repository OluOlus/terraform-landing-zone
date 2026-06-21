# Conformance Packs Main Module
# This module orchestrates all compliance framework conformance packs

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# The individual conformance packs and rules are defined in their respective .tf files:
# - ncsc.tf: Security Standards Cloud Security Principles implementation
# - uk-gdpr.tf: GDPR compliance implementation  
# - cyber-essentials.tf: Security Essentials compliance implementation

# This main.tf file serves as the entry point for the conformance packs module
# and can be used for any cross-framework configuration or dependencies
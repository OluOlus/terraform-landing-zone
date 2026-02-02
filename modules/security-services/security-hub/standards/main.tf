# Security Hub Standards Main Module
# This module orchestrates all compliance framework standards

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# The individual standards are defined in their respective .tf files:
# - ncsc.tf: Security Standards Cloud Security Principles implementation
# - cis-benchmark.tf: CIS AWS Foundations Benchmark implementation  
# - aws-foundational.tf: AWS Foundational Security Best Practices implementation

# This main.tf file serves as the entry point for the standards module
# and can be used for any cross-standard configuration or dependencies
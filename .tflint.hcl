# TFLint configuration for AWS Secure Landing Zone

config {
  call_module_type = "all"
  force = false
}

plugin "terraform" {
  enabled = true
}

plugin "aws" {
  enabled = true
  version = "0.32.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

# Configure rules
rule "terraform_required_version" {
  enabled = true
}

rule "terraform_required_providers" {
  enabled = true
}

rule "terraform_unused_declarations" {
  enabled = false  # Don't fail on unused variables (often used for future extensibility)
}

rule "terraform_deprecated_interpolation" {
  enabled = true
}

rule "terraform_module_version" {
  enabled = false  # Not applicable for local modules
}

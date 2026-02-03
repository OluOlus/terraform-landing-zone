# UK Data Residency Service Control Policy
# Restricts AWS service usage to UK-approved regions (eu-west-1, eu-west-2)
# Requirement: 3.1, 3.2 - UK Data Residency Enforcement

locals {
  uk_approved_regions = ["eu-west-1", "eu-west-2"]
  global_services = [
    "iam:*",
    "organizations:*",
    "route53:*",
    "cloudfront:*",
    "waf:*",
    "support:*",
    "trustedadvisor:*"
  ]
}

# UK Data Residency SCP Definition
data "aws_iam_policy_document" "uk_data_residency" {
  statement {
    sid       = "DenyNonUKRegions"
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]

    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = local.uk_approved_regions
    }

    condition {
      test     = "ForAllValues:StringNotEquals"
      variable = "aws:PrincipalTag/BreakGlass"
      values   = ["true"]
    }
  }

  statement {
    sid       = "AllowGlobalServices"
    effect    = "Allow"
    actions   = local.global_services
    resources = ["*"]
  }
}

# Output the policy document for use in the organization module
output "policy_document" {
  description = "The UK Data Residency SCP policy document"
  value       = data.aws_iam_policy_document.uk_data_residency.json
}

output "policy_name" {
  description = "The name of the UK Data Residency SCP"
  value       = "UK-Data-Residency-Policy"
}

output "policy_description" {
  description = "Description of the UK Data Residency SCP"
  value       = "Enforces UK data residency by restricting AWS services to eu-west-1 and eu-west-2 regions"
}

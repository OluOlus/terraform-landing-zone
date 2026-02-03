# Mandatory Tagging Service Control Policy
# Enforces mandatory tags on resource creation for compliance and cost management
# Requirement: 1.4, 11.1 - Mandatory Resource Tagging

locals {
  mandatory_tags = [
    "DataClassification",
    "Environment",
    "CostCenter",
    "Owner"
  ]

  tagging_enforced_actions = [
    "ec2:RunInstances",
    "rds:CreateDBInstance",
    "s3:CreateBucket",
    "lambda:CreateFunction",
    "ecs:CreateService",
    "eks:CreateCluster"
  ]
}

# Mandatory Tagging SCP Definition
data "aws_iam_policy_document" "mandatory_tagging" {
  statement {
    sid       = "RequireDataClassificationTag"
    effect    = "Deny"
    actions   = local.tagging_enforced_actions
    resources = ["*"]

    condition {
      test     = "Null"
      variable = "aws:RequestTag/DataClassification"
      values   = ["true"]
    }
  }

  statement {
    sid       = "RequireEnvironmentTag"
    effect    = "Deny"
    actions   = local.tagging_enforced_actions
    resources = ["*"]

    condition {
      test     = "Null"
      variable = "aws:RequestTag/Environment"
      values   = ["true"]
    }
  }

  statement {
    sid       = "RequireCostCenterTag"
    effect    = "Deny"
    actions   = local.tagging_enforced_actions
    resources = ["*"]

    condition {
      test     = "Null"
      variable = "aws:RequestTag/CostCenter"
      values   = ["true"]
    }
  }

  statement {
    sid       = "RequireOwnerTag"
    effect    = "Deny"
    actions   = local.tagging_enforced_actions
    resources = ["*"]

    condition {
      test     = "Null"
      variable = "aws:RequestTag/Owner"
      values   = ["true"]
    }
  }
}

# Output the policy document for use in the organization module
output "policy_document" {
  description = "The Mandatory Tagging SCP policy document"
  value       = data.aws_iam_policy_document.mandatory_tagging.json
}

output "policy_name" {
  description = "The name of the Mandatory Tagging SCP"
  value       = "UK-Mandatory-Tagging-Policy"
}

output "policy_description" {
  description = "Description of the Mandatory Tagging SCP"
  value       = "Enforces mandatory tagging for compliance including DataClassification, Environment, CostCenter, and Owner tags"
}

output "mandatory_tags_list" {
  description = "List of mandatory tags enforced by this policy"
  value       = local.mandatory_tags
}

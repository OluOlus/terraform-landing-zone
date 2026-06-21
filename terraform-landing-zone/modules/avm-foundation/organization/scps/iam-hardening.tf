# IAM Hardening Service Control Policy
# Enforces IAM security best practices including MFA and role protection
# Requirement: 9.1, 9.2, 9.3 - Identity and Access Management Security

locals {
  protected_roles = [
    "arn:aws:iam::*:role/uk-landing-zone-*",
    "arn:aws:iam::*:role/OrganizationAccountAccessRole",
    "arn:aws:iam::*:role/AWSControlTowerExecution",
    "arn:aws:iam::*:role/AWSServiceRole*"
  ]

  role_modification_actions = [
    "iam:DeleteRole",
    "iam:DeleteRolePolicy",
    "iam:DetachRolePolicy",
    "iam:PutRolePolicy",
    "iam:AttachRolePolicy",
    "iam:UpdateRole",
    "iam:UpdateRoleDescription",
    "iam:UpdateAssumeRolePolicy"
  ]

  sensitive_iam_actions = [
    "iam:CreateRole",
    "iam:DeleteRole",
    "iam:AttachRolePolicy",
    "iam:DetachRolePolicy",
    "iam:PutRolePolicy",
    "iam:DeleteRolePolicy",
    "iam:CreatePolicy",
    "iam:DeletePolicy",
    "iam:CreatePolicyVersion",
    "iam:DeletePolicyVersion",
    "iam:SetDefaultPolicyVersion"
  ]

  mfa_device_actions = [
    "iam:DeactivateMFADevice",
    "iam:DeleteVirtualMFADevice",
    "iam:ResyncMFADevice"
  ]
}

# IAM Hardening SCP Definition
data "aws_iam_policy_document" "iam_hardening" {
  statement {
    sid       = "DenyCreatingUsersWithoutMFA"
    effect    = "Deny"
    actions   = ["iam:CreateUser", "iam:CreateAccessKey"]
    resources = ["*"]

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["false"]
    }

    condition {
      test     = "ForAllValues:StringNotEquals"
      variable = "aws:PrincipalTag/BreakGlass"
      values   = ["true"]
    }
  }

  statement {
    sid       = "DenyModifyingCriticalRoles"
    effect    = "Deny"
    actions   = local.role_modification_actions
    resources = local.protected_roles

    condition {
      test     = "ForAllValues:StringNotEquals"
      variable = "aws:PrincipalTag/BreakGlass"
      values   = ["true"]
    }
  }

  statement {
    sid       = "DenyCreatingAdminPolicies"
    effect    = "Deny"
    actions   = ["iam:CreatePolicy", "iam:CreatePolicyVersion"]
    resources = ["*"]

    condition {
      test     = "ForAnyValue:StringLike"
      variable = "iam:PolicyDocument"
      values = [
        "*\"Effect\":\"Allow\"*\"Action\":\"*\"*\"Resource\":\"*\"*",
        "*\"Effect\":\"Allow\"*\"Action\":[\"*\"]*\"Resource\":\"*\"*",
        "*\"Effect\":\"Allow\"*\"Action\":[\"*\"]*\"Resource\":[\"*\"]*"
      ]
    }

    condition {
      test     = "ForAllValues:StringNotEquals"
      variable = "aws:PrincipalTag/BreakGlass"
      values   = ["true"]
    }
  }

  statement {
    sid       = "DenyDisablingMFA"
    effect    = "Deny"
    actions   = local.mfa_device_actions
    resources = ["*"]

    condition {
      test     = "ForAllValues:StringNotEquals"
      variable = "aws:PrincipalTag/BreakGlass"
      values   = ["true"]
    }
  }

  statement {
    sid       = "RequireMFAForSensitiveActions"
    effect    = "Deny"
    actions   = local.sensitive_iam_actions
    resources = ["*"]

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["false"]
    }

    condition {
      test     = "ForAllValues:StringNotEquals"
      variable = "aws:PrincipalTag/BreakGlass"
      values   = ["true"]
    }
  }
}

# Output the policy document for use in the organization module
output "policy_document" {
  description = "The IAM Hardening SCP policy document"
  value       = data.aws_iam_policy_document.iam_hardening.json
}

output "policy_name" {
  description = "The name of the IAM Hardening SCP"
  value       = "UK-IAM-Hardening-Policy"
}

output "policy_description" {
  description = "Description of the IAM Hardening SCP"
  value       = "Enforces IAM security best practices including MFA requirements, role protection, and prevents overly permissive policies"
}

output "protected_roles_list" {
  description = "List of role patterns protected by this policy"
  value       = local.protected_roles
}

# Service Restrictions Service Control Policy
# Restricts high-risk services and prevents disabling of security controls
# Requirement: 6.1 - Security Controls Protection

locals {
  high_risk_services = [
    "sagemaker:*",
    "comprehend:*",
    "rekognition:*",
    "textract:*",
    "transcribe:*",
    "translate:*",
    "polly:*",
    "lex:*",
    "connect:*",
    "chime:*",
    "workspaces:*",
    "workdocs:*",
    "workmail:*",
    "appstream:*",
    "worklink:*"
  ]

  cloudtrail_protection_actions = [
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
    "cloudtrail:PutEventSelectors"
  ]

  config_protection_actions = [
    "config:StopConfigurationRecorder",
    "config:DeleteConfigurationRecorder",
    "config:DeleteDeliveryChannel",
    "config:PutConfigurationRecorder",
    "config:PutDeliveryChannel"
  ]

  guardduty_protection_actions = [
    "guardduty:DeleteDetector",
    "guardduty:DeleteIPSet",
    "guardduty:DeleteThreatIntelSet",
    "guardduty:StopMonitoringMembers",
    "guardduty:UpdateDetector"
  ]
}

# Service Restrictions SCP Definition
data "aws_iam_policy_document" "service_restrictions" {
  statement {
    sid       = "DenyHighRiskServices"
    effect    = "Deny"
    actions   = local.high_risk_services
    resources = ["*"]

    condition {
      test     = "ForAllValues:StringNotEquals"
      variable = "aws:PrincipalTag/BreakGlass"
      values   = ["true"]
    }
  }

  statement {
    sid       = "DenyRootUserActions"
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalType"
      values   = ["Root"]
    }

    condition {
      test     = "ForAllValues:StringNotEquals"
      variable = "aws:PrincipalTag/BreakGlass"
      values   = ["true"]
    }
  }

  statement {
    sid       = "DenyDisablingCloudTrail"
    effect    = "Deny"
    actions   = local.cloudtrail_protection_actions
    resources = ["*"]

    condition {
      test     = "ForAllValues:StringNotEquals"
      variable = "aws:PrincipalTag/BreakGlass"
      values   = ["true"]
    }
  }

  statement {
    sid       = "DenyDisablingConfig"
    effect    = "Deny"
    actions   = local.config_protection_actions
    resources = ["*"]

    condition {
      test     = "ForAllValues:StringNotEquals"
      variable = "aws:PrincipalTag/BreakGlass"
      values   = ["true"]
    }
  }

  statement {
    sid       = "DenyDisablingGuardDuty"
    effect    = "Deny"
    actions   = local.guardduty_protection_actions
    resources = ["*"]

    condition {
      test     = "ForAllValues:StringNotEquals"
      variable = "aws:PrincipalTag/BreakGlass"
      values   = ["true"]
    }
  }

  statement {
    sid       = "DenyLeavingOrganization"
    effect    = "Deny"
    actions   = ["organizations:LeaveOrganization"]
    resources = ["*"]
  }
}

# Output the policy document for use in the organization module
output "policy_document" {
  description = "The Service Restrictions SCP policy document"
  value       = data.aws_iam_policy_document.service_restrictions.json
}

output "policy_name" {
  description = "The name of the Service Restrictions SCP"
  value       = "UK-Service-Restrictions-Policy"
}

output "policy_description" {
  description = "Description of the Service Restrictions SCP"
  value       = "Restricts access to high-risk AWS services and prevents disabling of security controls"
}

output "protected_services" {
  description = "List of services protected from being disabled"
  value       = ["CloudTrail", "AWS Config", "GuardDuty"]
}

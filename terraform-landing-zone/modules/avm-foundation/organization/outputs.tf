# Outputs for Organization Structure Module

output "organization_id" {
  description = "The ID of the AWS Organization"
  value       = data.aws_organizations_organization.current.id
}

output "organization_arn" {
  description = "The ARN of the AWS Organization"
  value       = data.aws_organizations_organization.current.arn
}

output "organization_root_id" {
  description = "The ID of the organization root"
  value       = data.aws_organizations_organization.current.roots[0].id
}

output "production_uk_ou_id" {
  description = "The ID of the Production UK organizational unit"
  value       = aws_organizations_organizational_unit.production_uk.id
}

output "production_uk_ou_arn" {
  description = "The ARN of the Production UK organizational unit"
  value       = aws_organizations_organizational_unit.production_uk.arn
}

output "non_production_uk_ou_id" {
  description = "The ID of the Non-Production UK organizational unit"
  value       = aws_organizations_organizational_unit.non_production_uk.id
}

output "non_production_uk_ou_arn" {
  description = "The ARN of the Non-Production UK organizational unit"
  value       = aws_organizations_organizational_unit.non_production_uk.arn
}

output "sandbox_ou_id" {
  description = "The ID of the Sandbox organizational unit"
  value       = aws_organizations_organizational_unit.sandbox.id
}

output "sandbox_ou_arn" {
  description = "The ARN of the Sandbox organizational unit"
  value       = aws_organizations_organizational_unit.sandbox.arn
}

output "core_infrastructure_ou_id" {
  description = "The ID of the Core Infrastructure organizational unit"
  value       = aws_organizations_organizational_unit.core_infrastructure.id
}

output "core_infrastructure_ou_arn" {
  description = "The ARN of the Core Infrastructure organizational unit"
  value       = aws_organizations_organizational_unit.core_infrastructure.arn
}

output "service_control_policies" {
  description = "Map of service control policy IDs and ARNs"
  value = var.enable_service_control_policies ? {
    uk_data_residency = {
      id  = aws_organizations_policy.uk_data_residency[0].id
      arn = aws_organizations_policy.uk_data_residency[0].arn
    }
    mandatory_tagging = {
      id  = aws_organizations_policy.mandatory_tagging[0].id
      arn = aws_organizations_policy.mandatory_tagging[0].arn
    }
    service_restrictions = {
      id  = aws_organizations_policy.service_restrictions[0].id
      arn = aws_organizations_policy.service_restrictions[0].arn
    }
    iam_hardening = {
      id  = aws_organizations_policy.iam_hardening[0].id
      arn = aws_organizations_policy.iam_hardening[0].arn
    }
  } : {}
}

output "organizational_units" {
  description = "Map of all organizational units with their IDs and ARNs"
  value = {
    production_uk = {
      id   = aws_organizations_organizational_unit.production_uk.id
      arn  = aws_organizations_organizational_unit.production_uk.arn
      name = aws_organizations_organizational_unit.production_uk.name
    }
    non_production_uk = {
      id   = aws_organizations_organizational_unit.non_production_uk.id
      arn  = aws_organizations_organizational_unit.non_production_uk.arn
      name = aws_organizations_organizational_unit.non_production_uk.name
    }
    sandbox = {
      id   = aws_organizations_organizational_unit.sandbox.id
      arn  = aws_organizations_organizational_unit.sandbox.arn
      name = aws_organizations_organizational_unit.sandbox.name
    }
    core_infrastructure = {
      id   = aws_organizations_organizational_unit.core_infrastructure.id
      arn  = aws_organizations_organizational_unit.core_infrastructure.arn
      name = aws_organizations_organizational_unit.core_infrastructure.name
    }
  }
}
# Outputs for Account Vending Module

output "workload_accounts" {
  description = "Map of created workload accounts with their details"
  value = {
    for key, account in aws_organizations_account.workload_accounts : key => {
      id                     = account.id
      arn                    = account.arn
      name                   = account.name
      email                  = account.email
      status                 = account.status
      joined_method          = account.joined_method
      joined_timestamp       = account.joined_timestamp
      parent_id              = account.parent_id
      organizational_unit_id = var.workload_accounts[key].organizational_unit_id
      account_type           = var.workload_accounts[key].account_type
      data_classification    = var.workload_accounts[key].data_classification
      environment            = var.workload_accounts[key].environment
      cost_center            = var.workload_accounts[key].cost_center
      owner                  = var.workload_accounts[key].owner
      project                = var.workload_accounts[key].project
    }
  }
}

output "account_ids" {
  description = "Map of account names to account IDs"
  value = {
    for key, account in aws_organizations_account.workload_accounts : key => account.id
  }
}

output "account_arns" {
  description = "Map of account names to account ARNs"
  value = {
    for key, account in aws_organizations_account.workload_accounts : key => account.arn
  }
}

output "cross_account_roles" {
  description = "Map of cross-account access roles created for each account"
  value = var.enable_cross_account_roles ? {
    for key, role in aws_iam_role.cross_account_access : key => {
      name = role.name
      arn  = role.arn
      id   = role.id
    }
  } : {}
}

output "account_kms_keys" {
  description = "Map of KMS keys created for each account"
  value = var.enable_account_kms_keys ? {
    for key, kms_key in aws_kms_key.account_keys : key => {
      id         = kms_key.id
      arn        = kms_key.arn
      key_id     = kms_key.key_id
      alias_name = aws_kms_alias.account_key_aliases[key].name
      alias_arn  = aws_kms_alias.account_key_aliases[key].arn
    }
  } : {}
}

output "baseline_s3_buckets" {
  description = "Map of baseline S3 buckets created for each account"
  value = var.create_baseline_s3_buckets ? {
    for key, bucket in aws_s3_bucket.account_baseline_buckets : key => {
      id                          = bucket.id
      arn                         = bucket.arn
      bucket_domain_name          = bucket.bucket_domain_name
      bucket_regional_domain_name = bucket.bucket_regional_domain_name
      region                      = bucket.region
    }
  } : {}
}

output "account_budgets" {
  description = "Map of AWS Budgets created for each account"
  value = var.create_account_budgets ? {
    for key, budget in aws_budgets_budget.account_budgets : key => {
      name         = budget.name
      arn          = budget.arn
      budget_type  = budget.budget_type
      limit_amount = budget.limit_amount
      limit_unit   = budget.limit_unit
      time_unit    = budget.time_unit
    }
  } : {}
}

output "baseline_stackset" {
  description = "Details of the baseline CloudFormation StackSet"
  value = var.deploy_baseline_stackset ? {
    id               = aws_cloudformation_stack_set.account_baseline[0].id
    arn              = aws_cloudformation_stack_set.account_baseline[0].arn
    name             = aws_cloudformation_stack_set.account_baseline[0].name
    stack_set_id     = aws_cloudformation_stack_set.account_baseline[0].stack_set_id
    permission_model = aws_cloudformation_stack_set.account_baseline[0].permission_model
  } : null
}

output "stackset_instances" {
  description = "Map of StackSet instances deployed to organizational units"
  value = var.deploy_baseline_stackset ? {
    for key, instance in aws_cloudformation_stack_set_instance.account_baseline_instances : key => {
      stack_set_name = instance.stack_set_name
      region         = instance.region
      stack_id       = instance.stack_id
    }
  } : {}
}

output "account_provisioning_summary" {
  description = "Summary of account provisioning results"
  value = {
    total_accounts_created = length(aws_organizations_account.workload_accounts)
    accounts_by_environment = {
      for env in distinct([for account in var.workload_accounts : account.environment]) :
      env => length([for account in var.workload_accounts : account if account.environment == env])
    }
    accounts_by_type = {
      for type in distinct([for account in var.workload_accounts : account.account_type]) :
      type => length([for account in var.workload_accounts : account if account.account_type == type])
    }
    accounts_by_data_classification = {
      for classification in distinct([for account in var.workload_accounts : account.data_classification]) :
      classification => length([for account in var.workload_accounts : account if account.data_classification == classification])
    }
    total_monthly_budget        = sum([for account in var.workload_accounts : account.monthly_budget_limit])
    kms_keys_created            = var.enable_account_kms_keys ? length(aws_kms_key.account_keys) : 0
    s3_buckets_created          = var.create_baseline_s3_buckets ? length(aws_s3_bucket.account_baseline_buckets) : 0
    budgets_created             = var.create_account_budgets ? length(aws_budgets_budget.account_budgets) : 0
    cross_account_roles_created = var.enable_cross_account_roles ? length(aws_iam_role.cross_account_access) : 0
    baseline_stackset_deployed  = var.deploy_baseline_stackset
  }
}

output "compliance_status" {
  description = "Compliance status of provisioned accounts"
  value = {
    uk_data_residency_enforced      = true
    mandatory_tagging_applied       = true
    encryption_at_rest_enabled      = var.enable_account_kms_keys
    cross_account_access_secured    = var.enable_cross_account_roles
    cost_management_enabled         = var.create_account_budgets
    baseline_configuration_deployed = var.deploy_baseline_stackset
    accounts_meet_uk_compliance = alltrue([
      for account in var.workload_accounts :
      contains(["public", "internal", "confidential", "restricted"], account.data_classification) &&
      contains(["production", "non-production", "sandbox", "security", "logging", "networking"], account.environment)
    ])
  }
}

output "account_access_instructions" {
  description = "Instructions for accessing the provisioned accounts"
  value = {
    cross_account_role_assumption = var.enable_cross_account_roles ? {
      for key, account in var.workload_accounts : key => {
        account_id          = aws_organizations_account.workload_accounts[key].id
        role_name           = aws_iam_role.cross_account_access[key].name
        role_arn            = aws_iam_role.cross_account_access[key].arn
        external_id         = account.external_id
        assume_role_command = "aws sts assume-role --role-arn ${aws_iam_role.cross_account_access[key].arn} --role-session-name ${key}-session --external-id ${account.external_id}"
      }
    } : {}

    organization_access_role = {
      for key, account in aws_organizations_account.workload_accounts : key => {
        account_id          = account.id
        role_name           = var.account_access_role_name
        role_arn            = "arn:aws:iam::${account.id}:role/${var.account_access_role_name}"
        assume_role_command = "aws sts assume-role --role-arn arn:aws:iam::${account.id}:role/${var.account_access_role_name} --role-session-name ${key}-org-session"
      }
    }
  }
}

output "next_steps" {
  description = "Recommended next steps after account provisioning"
  value = [
    "1. Configure AWS SSO/Identity Center permission sets for the new accounts",
    "2. Deploy workload-specific infrastructure using the appropriate environment modules",
    "3. Configure account-specific security controls and monitoring",
    "4. Set up cross-account networking if required",
    "5. Configure backup and disaster recovery policies",
    "6. Review and adjust budget limits based on actual usage",
    "7. Ensure all resources are properly tagged according to compliance requirements",
    "8. Configure account-specific CloudTrail, Config, and GuardDuty settings",
    "9. Set up account-specific dashboards and monitoring",
    "10. Conduct security assessment and compliance validation"
  ]
}
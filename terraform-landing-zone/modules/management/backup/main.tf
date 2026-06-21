# AWS Backup Module - UK Landing Zone Data Protection
# This module implements centralized backup management for the UK AWS Secure Landing Zone

# AWS Backup Vault
resource "aws_backup_vault" "main" {
  name        = var.vault_name
  kms_key_arn = var.vault_kms_key_arn

  tags = merge(var.common_tags, {
    Name               = var.vault_name
    Purpose            = "Centralized backup storage"
    DataClassification = "confidential"
  })
}

# Backup Vault Policy
resource "aws_backup_vault_policy" "main" {
  count             = var.vault_policy != null ? 1 : 0
  backup_vault_name = aws_backup_vault.main.name
  policy            = var.vault_policy
}

# Backup Plans
resource "aws_backup_plan" "plans" {
  for_each = var.backup_plans

  name = each.key

  dynamic "rule" {
    for_each = each.value.rules
    content {
      rule_name           = rule.value.rule_name
      target_vault_name   = aws_backup_vault.main.name
      schedule            = rule.value.schedule
      start_window        = rule.value.start_window
      completion_window   = rule.value.completion_window
      recovery_point_tags = merge(var.common_tags, rule.value.recovery_point_tags)

      dynamic "lifecycle" {
        for_each = rule.value.lifecycle != null ? [rule.value.lifecycle] : []
        content {
          cold_storage_after = lifecycle.value.cold_storage_after
          delete_after       = lifecycle.value.delete_after
        }
      }

      dynamic "copy_action" {
        for_each = rule.value.copy_actions != null ? rule.value.copy_actions : []
        content {
          destination_vault_arn = copy_action.value.destination_vault_arn
          lifecycle {
            cold_storage_after = copy_action.value.lifecycle.cold_storage_after
            delete_after       = copy_action.value.lifecycle.delete_after
          }
        }
      }
    }
  }

  advanced_backup_setting {
    backup_options = {
      WindowsVSS = "enabled"
    }
    resource_type = "EC2"
  }

  tags = var.common_tags
}

# Backup Selection
resource "aws_backup_selection" "selections" {
  for_each = var.backup_selections

  name         = each.key
  plan_id      = aws_backup_plan.plans[each.value.plan_name].id
  iam_role_arn = each.value.iam_role_arn

  dynamic "selection_tag" {
    for_each = each.value.selection_tags
    content {
      type  = "STRINGEQUALS"
      key   = selection_tag.value.key
      value = selection_tag.value.value
    }
  }

  resources = each.value.resources
}

# Secondary Backup Vault (for cross-region replication)
resource "aws_backup_vault" "secondary" {
  count       = var.create_secondary_vault ? 1 : 0
  provider    = aws.replica
  name        = "${var.vault_name}-replica"
  kms_key_arn = var.secondary_vault_kms_key_arn

  tags = merge(var.common_tags, {
    Name               = "${var.vault_name}-replica"
    Purpose            = "Secondary backup storage"
    DataClassification = "confidential"
    Region             = var.secondary_vault_region
  })
}

# Backup Framework
resource "aws_backup_framework" "main" {
  count = var.create_backup_framework ? 1 : 0
  name  = var.framework_name

  dynamic "control" {
    for_each = var.framework_controls
    content {
      name = control.value.name

      dynamic "input_parameter" {
        for_each = control.value.input_parameters
        content {
          name  = input_parameter.value.name
          value = input_parameter.value.value
        }
      }

      dynamic "scope" {
        for_each = control.value.scope != null ? [control.value.scope] : []
        content {
          compliance_resource_ids   = scope.value.compliance_resource_ids
          compliance_resource_types = scope.value.compliance_resource_types
          tags                      = scope.value.tags
        }
      }
    }
  }

  tags = var.common_tags
}

# Backup Report Plan
resource "aws_backup_report_plan" "main" {
  count = var.create_report_plan ? 1 : 0
  name  = var.report_plan_name

  report_delivery_channel {
    formats        = var.report_formats
    s3_bucket_name = var.report_s3_bucket_name
    s3_key_prefix  = var.report_s3_key_prefix
  }

  report_setting {
    report_template = var.report_template
  }

  tags = var.common_tags
}

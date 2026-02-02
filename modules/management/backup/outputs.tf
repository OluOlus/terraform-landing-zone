# AWS Backup Module Outputs

output "vault_id" {
  description = "ID of the backup vault"
  value       = aws_backup_vault.main.id
}

output "vault_arn" {
  description = "ARN of the backup vault"
  value       = aws_backup_vault.main.arn
}

output "secondary_vault_arn" {
  description = "ARN of the secondary backup vault"
  value       = var.create_secondary_vault ? aws_backup_vault.secondary[0].arn : null
}

output "backup_plan_arns" {
  description = "Map of backup plan names to ARNs"
  value       = { for k, v in aws_backup_plan.plans : k => v.arn }
}

output "backup_framework_arn" {
  description = "ARN of the backup framework"
  value       = var.create_backup_framework ? aws_backup_framework.main[0].arn : null
}

output "report_plan_arn" {
  description = "ARN of the backup report plan"
  value       = var.create_report_plan ? aws_backup_report_plan.main[0].arn : null
}

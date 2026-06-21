# Non-Production UK Environment Outputs

output "vpc_id" {
  description = "ID of the non-production VPC"
  value       = module.vpc.vpc_id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = module.vpc.private_subnet_ids
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = module.vpc.public_subnet_ids
}

output "database_subnet_ids" {
  description = "IDs of the database subnets"
  value       = module.vpc.database_subnet_ids
}

output "kms_logs_key_arn" {
  description = "ARN of the KMS key for logs"
  value       = module.kms_logs.key_arn
}

output "kms_s3_key_arn" {
  description = "ARN of the KMS key for S3"
  value       = module.kms_s3.key_arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for alerts"
  value       = module.cloudwatch.sns_topic_arn
}

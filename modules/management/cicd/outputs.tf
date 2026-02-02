# Outputs for CI/CD Module

output "cicd_artifacts_bucket_name" {
  description = "Name of the S3 bucket for CI/CD artifacts"
  value       = aws_s3_bucket.cicd_artifacts.bucket
}

output "cicd_artifacts_bucket_arn" {
  description = "ARN of the S3 bucket for CI/CD artifacts"
  value       = aws_s3_bucket.cicd_artifacts.arn
}

output "account_provisioning_project_name" {
  description = "Name of the account provisioning CodeBuild project"
  value       = aws_codebuild_project.account_provisioning.name
}

output "security_scanning_project_name" {
  description = "Name of the security scanning CodeBuild project"
  value       = aws_codebuild_project.security_scanning.name
}

output "compliance_checking_project_name" {
  description = "Name of the compliance checking CodeBuild project"
  value       = aws_codebuild_project.compliance_checking.name
}

output "pipeline_name" {
  description = "Name of the CodePipeline"
  value       = aws_codepipeline.landing_zone_pipeline.name
}

output "pipeline_arn" {
  description = "ARN of the CodePipeline"
  value       = aws_codepipeline.landing_zone_pipeline.arn
}

output "codebuild_role_arn" {
  description = "ARN of the CodeBuild IAM role"
  value       = aws_iam_role.codebuild_role.arn
}

output "codepipeline_role_arn" {
  description = "ARN of the CodePipeline IAM role"
  value       = aws_iam_role.codepipeline_role.arn
}
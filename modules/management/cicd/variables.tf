# Variables for CI/CD Module

variable "environment" {
  description = "Environment name (e.g., production, staging, development)"
  type        = string
}

variable "aws_region" {
  description = "AWS region for CI/CD resources"
  type        = string
  default     = "us-east-1"
}

variable "tags" {
  description = "Tags to apply to all CI/CD resources"
  type        = map(string)
  default     = {}
}

variable "github_owner" {
  description = "GitHub repository owner"
  type        = string
  default     = ""
}

variable "github_repo" {
  description = "GitHub repository name"
  type        = string
  default     = ""
}

variable "github_branch" {
  description = "GitHub branch to track"
  type        = string
  default     = "main"
}

variable "github_token" {
  description = "GitHub personal access token"
  type        = string
  sensitive   = true
  default     = ""
}

variable "enable_pipeline" {
  description = "Enable CodePipeline for automated deployments"
  type        = bool
  default     = false
}

variable "codebuild_compute_type" {
  description = "CodeBuild compute type"
  type        = string
  default     = "BUILD_GENERAL1_MEDIUM"
}

variable "codebuild_image" {
  description = "CodeBuild Docker image"
  type        = string
  default     = "aws/codebuild/amazonlinux2-x86_64-standard:3.0"
}
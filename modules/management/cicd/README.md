# CI/CD Module

AWS CodePipeline and CodeBuild pipelines for automated Terraform deployment with security scanning gates.

## Features

- CodePipeline for environment-specific deployments
- CodeBuild stages: Terraform validate → tfsec scan → checkov scan → plan → apply (gated)
- IAM roles with least-privilege for pipeline execution
- Secrets Manager integration for deployment credentials
- SNS notifications for pipeline events
- Separate pipelines for: account-provisioning, security-scanning, compliance-checking

## Usage

```hcl
module "cicd" {
  source = "../../modules/management/cicd"

  environment             = "management"
  aws_region              = "eu-west-2"
  pipeline_name           = "uk-landing-zone-deployment"
  source_repo_name        = "terraform-landing-zone"
  notification_sns_arn    = module.monitoring.sns_topic_arn
  tags                    = local.common_tags
}
```

## Compliance

- NCSC Principle 7: Secure development
- NCSC Principle 10: Identity and authentication

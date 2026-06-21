# Management Account Module

Configures the AWS root management account with AWS Organizations, consolidated billing, and UK-compliant baseline settings.

## Features

- AWS Organizations root account setup with consolidated billing
- Service access principals for delegated services (GuardDuty, Security Hub, Config, Macie)
- UK-specific organizational units: Production-UK, Non-Production-UK, Sandbox
- Mandatory tagging enforcement via service control policies
- CloudWatch alarms for root account and unauthorized API activity
- Cost anomaly detection and budget alerting

## Usage

```hcl
module "management_account" {
  source = "../../modules/avm-foundation/management-account"

  organization_name = "UK Secure Landing Zone"
  common_tags       = local.common_tags
}
```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.5.0 |
| aws | ~> 5.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| organization\_name | Name of the AWS Organization | `string` | n/a | yes |
| common\_tags | Common tags applied to all resources | `map(string)` | `{}` | no |
| aws\_regions | Allowed AWS regions for UK data residency | `list(string)` | `["eu-west-2","eu-west-1"]` | no |

## Outputs

| Name | Description |
|------|-------------|
| organization\_id | AWS Organizations ID |
| management\_account\_id | Management account ID |
| root\_id | Root ID of the organization |

## Compliance

- NCSC Cloud Security Principles: Principle 2 (Governance), Principle 9 (Secure user management)
- UK GDPR: Data residency enforcement, audit logging
- Cyber Essentials: Access control, secure configuration

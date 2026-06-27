# AWS Control Tower Module

This module optionally creates an AWS Control Tower landing zone and enables selected Control Tower controls.

Use this module only from the management account. When Control Tower is enabled, let Control Tower own the baseline OU and guardrail lifecycle; do not also manage the same OUs and guardrails through the custom Organizations module.

## Example

```hcl
module "control_tower" {
  source = "../../modules/avm-foundation/control-tower"

  enabled                = true
  landing_zone_version   = "3.3"
  governed_regions       = ["eu-west-2", "eu-west-1"]
  log_archive_account_id = "111111111111"
  audit_account_id       = "222222222222"

  enabled_controls = {
    require_encrypted_volumes = {
      control_identifier = "arn:aws:controltower:eu-west-2::control/<CONTROL_ID>"
      target_identifier  = "arn:aws:organizations::<MANAGEMENT_ACCOUNT_ID>:ou/<ROOT_ID>/<OU_ID>"
    }
  }

  common_tags = local.common_tags
}
```

Before enabling, confirm the currently supported Control Tower landing zone version for your AWS account and region.

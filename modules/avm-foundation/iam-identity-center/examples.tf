# Example usage of the IAM Identity Center module
# This file demonstrates how to use the module with typical UK Landing Zone configuration

/*
# Example 1: Basic usage with default settings
module "iam_identity_center_basic" {
  source = "./modules/avm-foundation/iam-identity-center"
  
  common_tags = {
    Environment        = "management"
    DataClassification = "internal"
    CostCenter        = "security"
    Owner             = "security-team"
    Project           = "uk-landing-zone"
  }
}

# Example 2: Full configuration with custom settings
module "iam_identity_center_full" {
  source = "./modules/avm-foundation/iam-identity-center"
  
  common_tags = {
    Environment        = "management"
    DataClassification = "internal"
    CostCenter        = "security"
    Owner             = "security-team"
    Project           = "uk-landing-zone"
    Compliance        = "UK-Security Standards"
  }
  
  enable_break_glass_monitoring = true
  break_glass_alarm_actions     = [
    "arn:aws:sns:us-east-1:123456789012:security-alerts",
    "arn:aws:sns:us-west-2:123456789012:security-alerts-backup"
  ]
  
  session_durations = {
    security_admin = "PT4H"
    network_admin  = "PT4H"
    developer      = "PT8H"
    viewer         = "PT12H"
    break_glass    = "PT1H"
  }
  
  mfa_max_age_seconds = {
    security_admin = 3600   # 1 hour
    network_admin  = 3600   # 1 hour
    developer      = 7200   # 2 hours
    viewer         = 28800  # 8 hours
    break_glass    = 300    # 5 minutes
  }
}

# Example 3: Account assignments for permission sets
resource "aws_ssoadmin_account_assignment" "security_admin_security_account" {
  instance_arn       = module.iam_identity_center_full.instance_arn
  permission_set_arn = module.iam_identity_center_full.security_admin_permission_set_arn
  
  principal_id   = "12345678-1234-1234-1234-123456789012"  # Security Admin Group ID
  principal_type = "GROUP"
  
  target_id   = "123456789012"  # Security Tooling Account ID
  target_type = "AWS_ACCOUNT"
}

resource "aws_ssoadmin_account_assignment" "network_admin_network_account" {
  instance_arn       = module.iam_identity_center_full.instance_arn
  permission_set_arn = module.iam_identity_center_full.network_admin_permission_set_arn
  
  principal_id   = "12345678-1234-1234-1234-123456789013"  # Network Admin Group ID
  principal_type = "GROUP"
  
  target_id   = "123456789013"  # Network Hub Account ID
  target_type = "AWS_ACCOUNT"
}

resource "aws_ssoadmin_account_assignment" "developer_dev_account" {
  instance_arn       = module.iam_identity_center_full.instance_arn
  permission_set_arn = module.iam_identity_center_full.developer_permission_set_arn
  
  principal_id   = "12345678-1234-1234-1234-123456789014"  # Developer Group ID
  principal_type = "GROUP"
  
  target_id   = "123456789014"  # Non-Production UK Account ID
  target_type = "AWS_ACCOUNT"
}

resource "aws_ssoadmin_account_assignment" "viewer_all_accounts" {
  for_each = toset([
    "123456789012",  # Security Account
    "123456789013",  # Network Account
    "123456789014",  # Non-Production Account
    "123456789015",  # Production Account
  ])
  
  instance_arn       = module.iam_identity_center_full.instance_arn
  permission_set_arn = module.iam_identity_center_full.viewer_permission_set_arn
  
  principal_id   = "12345678-1234-1234-1234-123456789015"  # Viewer Group ID
  principal_type = "GROUP"
  
  target_id   = each.value
  target_type = "AWS_ACCOUNT"
}

resource "aws_ssoadmin_account_assignment" "break_glass_management_account" {
  instance_arn       = module.iam_identity_center_full.instance_arn
  permission_set_arn = module.iam_identity_center_full.break_glass_permission_set_arn
  
  principal_id   = "12345678-1234-1234-1234-123456789016"  # Break Glass Group ID
  principal_type = "GROUP"
  
  target_id   = "123456789010"  # Management Account ID
  target_type = "AWS_ACCOUNT"
}

# Example 4: SNS topic for break glass alerts
resource "aws_sns_topic" "security_alerts" {
  name = "uk-landing-zone-security-alerts"
  
  tags = {
    Environment        = "management"
    DataClassification = "internal"
    CostCenter        = "security"
    Owner             = "security-team"
    Project           = "uk-landing-zone"
    Purpose           = "SecurityAlerting"
  }
}

resource "aws_sns_topic_subscription" "security_alerts_email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = "security-team@company.co.uk"
}

# Example 5: Identity Store groups (if managing users/groups via Terraform)
resource "aws_identitystore_group" "security_admins" {
  display_name      = "SecurityAdministrators"
  description       = "Security administrators with full access to security services"
  identity_store_id = module.iam_identity_center_full.identity_store_id
}

resource "aws_identitystore_group" "network_admins" {
  display_name      = "NetworkAdministrators"
  description       = "Network administrators with full access to networking services"
  identity_store_id = module.iam_identity_center_full.identity_store_id
}

resource "aws_identitystore_group" "developers" {
  display_name      = "Developers"
  description       = "Developers with limited access to development resources"
  identity_store_id = module.iam_identity_center_full.identity_store_id
}

resource "aws_identitystore_group" "viewers" {
  display_name      = "ReadOnlyViewers"
  description       = "Users with read-only access across all accounts"
  identity_store_id = module.iam_identity_center_full.identity_store_id
}

resource "aws_identitystore_group" "break_glass" {
  display_name      = "BreakGlassEmergency"
  description       = "Emergency access group for break glass scenarios"
  identity_store_id = module.iam_identity_center_full.identity_store_id
}
*/
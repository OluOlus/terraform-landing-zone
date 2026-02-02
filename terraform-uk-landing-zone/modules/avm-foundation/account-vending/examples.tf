# Example configurations for the Account Vending Module
# These examples demonstrate different use cases for account provisioning

# Example 1: Basic workload account provisioning
locals {
  example_basic_accounts = {
    production_web = {
      name                      = "Production-Web-Application"
      email                     = "aws-prod-web@company.com"
      organizational_unit_id    = "ou-example-production"
      account_type              = "workload"
      data_classification       = "confidential"
      environment               = "production"
      cost_center               = "WEB-001"
      owner                     = "web-team@company.com"
      project                   = "Web-Platform"
      monthly_budget_limit      = 3000
      budget_notification_email = "finance@company.com"
      external_id               = "prod-web-12345"
    }

    dev_web = {
      name                      = "Development-Web-Application"
      email                     = "aws-dev-web@company.com"
      organizational_unit_id    = "ou-example-nonprod"
      account_type              = "workload"
      data_classification       = "internal"
      environment               = "non-production"
      cost_center               = "WEB-001"
      owner                     = "web-team@company.com"
      project                   = "Web-Platform"
      monthly_budget_limit      = 800
      budget_notification_email = "finance@company.com"
      external_id               = "dev-web-67890"
    }
  }
}

# Example 2: Infrastructure accounts (Security, Logging, Networking)
locals {
  example_infrastructure_accounts = {
    security_tooling = {
      name                      = "Security-Tooling"
      email                     = "aws-security@company.com"
      organizational_unit_id    = "ou-example-core-infra"
      account_type              = "security"
      data_classification       = "restricted"
      environment               = "security"
      cost_center               = "SEC-001"
      owner                     = "security-team@company.com"
      project                   = "Security-Infrastructure"
      backup_schedule           = "continuous"
      maintenance_window        = "sun:02:00-sun:03:00"
      monthly_budget_limit      = 2000
      budget_notification_email = "security-finance@company.com"
      external_id               = "sec-tool-abcde"
      tags = {
        SecurityLevel = "High"
        Monitoring    = "24x7"
        Compliance    = "SOC2-PCI"
      }
    }

    log_archive = {
      name                      = "Log-Archive"
      email                     = "aws-logging@company.com"
      organizational_unit_id    = "ou-example-core-infra"
      account_type              = "logging"
      data_classification       = "restricted"
      environment               = "logging"
      cost_center               = "LOG-001"
      owner                     = "platform-team@company.com"
      project                   = "Logging-Infrastructure"
      backup_schedule           = "daily"
      maintenance_window        = "sun:01:00-sun:02:00"
      monthly_budget_limit      = 1500
      budget_notification_email = "platform-finance@company.com"
      external_id               = "log-arch-fghij"
      tags = {
        RetentionPeriod = "7-years"
        DataType        = "Audit-Logs"
      }
    }

    network_hub = {
      name                      = "Network-Hub"
      email                     = "aws-networking@company.com"
      organizational_unit_id    = "ou-example-core-infra"
      account_type              = "networking"
      data_classification       = "confidential"
      environment               = "networking"
      cost_center               = "NET-001"
      owner                     = "network-team@company.com"
      project                   = "Network-Infrastructure"
      backup_schedule           = "daily"
      maintenance_window        = "sun:03:00-sun:04:00"
      monthly_budget_limit      = 1200
      budget_notification_email = "network-finance@company.com"
      external_id               = "net-hub-klmno"
      tags = {
        NetworkType  = "Hub-and-Spoke"
        Connectivity = "Hybrid"
      }
    }
  }
}

# Example 3: Multi-environment application accounts
locals {
  example_multi_env_accounts = {
    prod_api = {
      name                      = "Production-API-Services"
      email                     = "aws-prod-api@company.com"
      organizational_unit_id    = "ou-example-production"
      account_type              = "workload"
      data_classification       = "confidential"
      environment               = "production"
      cost_center               = "API-001"
      owner                     = "api-team@company.com"
      project                   = "API-Platform"
      backup_schedule           = "continuous"
      maintenance_window        = "sun:04:00-sun:05:00"
      monthly_budget_limit      = 5000
      budget_notification_email = "api-finance@company.com"
      external_id               = "prod-api-pqrst"
      tags = {
        ServiceType     = "REST-API"
        SLA             = "99.9"
        DataSensitivity = "High"
      }
    }

    staging_api = {
      name                      = "Staging-API-Services"
      email                     = "aws-staging-api@company.com"
      organizational_unit_id    = "ou-example-nonprod"
      account_type              = "workload"
      data_classification       = "internal"
      environment               = "non-production"
      cost_center               = "API-001"
      owner                     = "api-team@company.com"
      project                   = "API-Platform"
      backup_schedule           = "daily"
      maintenance_window        = "sat:02:00-sat:04:00"
      monthly_budget_limit      = 1500
      budget_notification_email = "api-finance@company.com"
      external_id               = "stg-api-uvwxy"
      tags = {
        ServiceType = "REST-API"
        Purpose     = "Pre-Production-Testing"
      }
    }

    dev_api = {
      name                      = "Development-API-Services"
      email                     = "aws-dev-api@company.com"
      organizational_unit_id    = "ou-example-nonprod"
      account_type              = "workload"
      data_classification       = "internal"
      environment               = "non-production"
      cost_center               = "API-001"
      owner                     = "api-team@company.com"
      project                   = "API-Platform"
      backup_schedule           = "weekly"
      maintenance_window        = "sat:01:00-sat:02:00"
      monthly_budget_limit      = 800
      budget_notification_email = "api-finance@company.com"
      external_id               = "dev-api-zabcd"
      tags = {
        ServiceType  = "REST-API"
        Purpose      = "Development-Testing"
        AutoShutdown = "Enabled"
      }
    }
  }
}

# Example 4: Sandbox and experimentation accounts
locals {
  example_sandbox_accounts = {
    innovation_sandbox = {
      name                      = "Innovation-Sandbox"
      email                     = "aws-innovation@company.com"
      organizational_unit_id    = "ou-example-sandbox"
      account_type              = "workload"
      data_classification       = "internal"
      environment               = "sandbox"
      cost_center               = "INN-001"
      owner                     = "innovation-team@company.com"
      project                   = "Innovation-Lab"
      backup_schedule           = "none"
      maintenance_window        = "daily:02:00-daily:03:00"
      monthly_budget_limit      = 500
      budget_notification_email = "innovation-finance@company.com"
      external_id               = "inn-sand-efghi"
      tags = {
        Purpose          = "Experimentation"
        AutoCleanup      = "Enabled"
        CostOptimization = "Aggressive"
      }
    }

    training_sandbox = {
      name                      = "Training-Sandbox"
      email                     = "aws-training@company.com"
      organizational_unit_id    = "ou-example-sandbox"
      account_type              = "workload"
      data_classification       = "public"
      environment               = "sandbox"
      cost_center               = "TRN-001"
      owner                     = "training-team@company.com"
      project                   = "AWS-Training"
      backup_schedule           = "none"
      maintenance_window        = "daily:01:00-daily:02:00"
      monthly_budget_limit      = 300
      budget_notification_email = "training-finance@company.com"
      external_id               = "trn-sand-jklmn"
      tags = {
        Purpose       = "Training-Education"
        AutoCleanup   = "Daily"
        StudentAccess = "Enabled"
      }
    }
  }
}

# Example usage with the module
/*
module "basic_account_vending" {
  source = "./modules/avm-foundation/account-vending"

  workload_accounts = local.example_basic_accounts
  
  security_account_id = "123456789012"
  logging_account_id  = "123456789013"
  
  enable_account_kms_keys     = true
  create_baseline_s3_buckets  = true
  create_account_budgets      = true
  deploy_baseline_stackset    = true
  
  organizational_unit_deployments = {
    production = {
      ou_id  = "ou-example-production"
      region = "us-east-1"
    }
    non_production = {
      ou_id  = "ou-example-nonprod"
      region = "us-east-1"
    }
  }
  
  common_tags = {
    Project             = "UK-AWS-Secure-Landing-Zone"
    ManagedBy           = "Terraform"
    ComplianceFramework = "Security Standards-Cloud-Security-Principles"
    DataResidency       = "UK"
    CostCenter          = "PLATFORM-001"
    Owner               = "platform-team@company.com"
  }
}

module "infrastructure_account_vending" {
  source = "./modules/avm-foundation/account-vending"

  workload_accounts = local.example_infrastructure_accounts
  
  security_account_id = "123456789012"
  logging_account_id  = "123456789013"
  
  # Enhanced security for infrastructure accounts
  enable_account_kms_keys     = true
  create_baseline_s3_buckets  = true
  create_account_budgets      = true
  deploy_baseline_stackset    = true
  enable_cross_account_roles  = true
  
  # Longer retention for infrastructure accounts
  s3_lifecycle_expiration_days = 3650  # 10 years
  kms_key_deletion_window     = 30     # Maximum retention
  
  organizational_unit_deployments = {
    core_infrastructure = {
      ou_id  = "ou-example-core-infra"
      region = "us-east-1"
    }
  }
  
  notification_email = "platform-alerts@company.com"
  
  common_tags = {
    Project             = "UK-AWS-Secure-Landing-Zone"
    ManagedBy           = "Terraform"
    ComplianceFramework = "Security Standards-Cloud-Security-Principles"
    DataResidency       = "UK"
    CostCenter          = "INFRASTRUCTURE-001"
    Owner               = "platform-team@company.com"
    CriticalityLevel    = "High"
  }
}
*/
# Networking Environment Configuration
# Configures the Network Hub Account with Transit Gateway, Network Firewall, and DNS

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    # Backend configuration via backend config file
  }
}

# Primary Provider (eu-west-2 - London)
provider "aws" {
  region = "eu-west-2"

  default_tags {
    tags = local.common_tags
  }
}

# Replica Provider (eu-west-1 - Ireland) for cross-region
provider "aws" {
  alias  = "replica"
  region = "eu-west-1"

  default_tags {
    tags = local.common_tags
  }
}

locals {
  environment = "networking"
  project     = "uk-landing-zone"

  common_tags = {
    Environment        = "networking"
    Project            = "uk-landing-zone"
    ManagedBy          = "Terraform"
    DataClassification = "internal"
    CostCenter         = "network-operations"
    Owner              = var.owner_email
    Compliance         = "NCSC-UK-GDPR"
  }
}

# Data Sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_organizations_organization" "current" {}

# KMS Key for Network Logs
module "kms_network" {
  source = "../../modules/security/kms"

  providers = {
    aws         = aws
    aws.replica = aws.replica
  }

  key_name                     = "network-logs"
  key_alias                    = "network-logs"
  key_description              = "KMS key for network log encryption"
  key_purpose                  = "Network log encryption"
  allow_cloudwatch_logs_access = true
  allow_vpc_flow_logs_access   = true
  enable_key_rotation          = true
  common_tags                  = local.common_tags
}

# Network Hub VPC
module "network_vpc" {
  source = "../../modules/networking/vpc"

  vpc_name              = "network-hub-vpc"
  vpc_cidr              = var.network_hub_cidr
  public_subnet_cidrs   = var.public_subnet_cidrs
  private_subnet_cidrs  = var.private_subnet_cidrs
  database_subnet_cidrs = var.database_subnet_cidrs

  enable_nat_gateway   = true
  single_nat_gateway   = false
  enable_flow_logs     = true
  flow_logs_kms_key_id = module.kms_network.key_arn

  common_tags = local.common_tags
}

# Transit Gateway
module "transit_gateway" {
  source = "../../modules/networking/transit-gateway"

  tgw_name        = "uk-landing-zone-tgw"
  tgw_description = "UK Landing Zone centralized network hub"

  amazon_side_asn                  = 64512
  default_route_table_association  = "disable"
  default_route_table_propagation  = "disable"
  vpn_ecmp_support                 = "enable"
  auto_accept_shared_attachments   = "enable"

  # Route table configuration
  create_production_route_table     = true
  create_non_production_route_table = true
  create_shared_services_route_table = true
  create_sandbox_route_table        = true

  # RAM sharing for organization
  enable_ram_share = true
  ram_principal_associations = [
    data.aws_organizations_organization.current.arn
  ]

  # Flow logs
  enable_flow_logs           = true
  flow_logs_destination_type = "cloud-watch-logs"
  flow_logs_retention_days   = 2555 # 7 years
  flow_logs_kms_key_id       = module.kms_network.key_id

  common_tags = local.common_tags
}

# Network Firewall
module "network_firewall" {
  source = "../../modules/networking/network-firewall"

  firewall_name        = "uk-landing-zone-firewall"
  firewall_policy_name = "uk-landing-zone-firewall-policy"

  vpc_id          = module.network_vpc.vpc_id
  subnet_mappings = module.network_vpc.private_subnet_ids

  # Protection settings
  delete_protection                 = true
  subnet_change_protection          = true
  firewall_policy_change_protection = true

  # UK-specific rules
  create_uk_stateless_rules = true
  enable_domain_filtering   = true
  enable_suricata_rules     = true

  # Logging
  enable_alert_logging = true
  enable_flow_logging  = true
  log_retention_days   = 2555 # 7 years
  log_kms_key_id       = module.kms_network.key_id

  # Alarms
  enable_cloudwatch_alarms = true
  alarm_sns_topic_arns     = [module.cloudwatch.sns_topic_arn]

  common_tags = local.common_tags
}

# DNS Resolution
module "dns" {
  source = "../../modules/networking/dns"

  resolver_name = "uk-landing-zone-dns"

  # Private hosted zones
  private_zones = {
    internal = {
      domain_name = var.private_hosted_zone_name
      vpc_associations = [
        {
          vpc_id     = module.network_vpc.vpc_id
          vpc_region = "eu-west-2"
        }
      ]
    }
  }

  # Resolver endpoints (optional - enable when needed)
  create_inbound_endpoint  = var.enable_dns_resolver_endpoints
  create_outbound_endpoint = var.enable_dns_resolver_endpoints
  inbound_subnet_ids       = var.enable_dns_resolver_endpoints ? module.network_vpc.private_subnet_ids : []
  outbound_subnet_ids      = var.enable_dns_resolver_endpoints ? module.network_vpc.private_subnet_ids : []

  # Query logging
  enable_query_logging       = true
  query_log_destination_type = "cloudwatch"
  query_log_retention_days   = 2555 # 7 years
  query_log_kms_key_id       = module.kms_network.key_id

  common_tags = local.common_tags
}

# CloudWatch for Network Monitoring
module "cloudwatch" {
  source = "../../modules/management/cloudwatch"

  log_groups = {
    transit_gateway = {
      name           = "/aws/transit-gateway/flow-logs"
      retention_days = 2555 # 7 years
      kms_key_id     = module.kms_network.key_arn
      purpose        = "Transit Gateway flow logs"
    }
    network_firewall_alerts = {
      name           = "/aws/network-firewall/alerts"
      retention_days = 2555
      kms_key_id     = module.kms_network.key_arn
      purpose        = "Network Firewall alerts"
    }
    network_firewall_flows = {
      name           = "/aws/network-firewall/flows"
      retention_days = 2555
      kms_key_id     = module.kms_network.key_arn
      purpose        = "Network Firewall flow logs"
    }
    vpc_flow_logs = {
      name           = "/aws/vpc/network-hub"
      retention_days = 2555
      kms_key_id     = module.kms_network.key_arn
      purpose        = "Network Hub VPC flow logs"
    }
  }

  create_sns_topic = true
  sns_topic_name   = "network-alerts"
  sns_kms_key_id   = module.kms_network.key_arn

  sns_subscriptions = {
    network_team = {
      protocol = "email"
      endpoint = var.network_team_email
    }
  }

  common_tags = local.common_tags
}

# Monitoring Dashboard
module "monitoring" {
  source = "../../modules/management/monitoring"

  environment = local.environment

  enable_security_monitoring   = true
  enable_compliance_monitoring = false
  enable_cost_monitoring       = true

  notification_email = var.network_team_email

  tags = local.common_tags
}

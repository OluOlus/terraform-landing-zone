# VPC Module

This module creates a secure, multi-tier VPC with public, private, and database subnets across multiple Availability Zones.

## Features

- Multi-AZ deployment for high availability
- Public, private, and database subnet tiers
- NAT Gateways for private subnet internet access
- VPC Flow Logs for network monitoring
- Route tables with appropriate routing
- Security groups for network access control
- Network ACLs for additional security layer

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         VPC                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │   Public Tier   │  │  Private Tier   │  │ Database Tier│ │
│  │                 │  │                 │  │              │ │
│  │ ┌─────┐ ┌─────┐ │  │ ┌─────┐ ┌─────┐ │  │ ┌────┐ ┌────┐│ │
│  │ │ AZ-A│ │ AZ-B│ │  │ │ AZ-A│ │ AZ-B│ │  │ │AZ-A│ │AZ-B││ │
│  │ └─────┘ └─────┘ │  │ └─────┘ └─────┘ │  │ └────┘ └────┘│ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Usage

```hcl
module "vpc" {
  source = "./modules/networking/vpc"

  vpc_name = "landing-zone-vpc"
  vpc_cidr = "10.0.0.0/16"
  
  public_subnet_cidrs   = ["10.0.1.0/24", "10.0.2.0/24"]
  private_subnet_cidrs  = ["10.0.10.0/24", "10.0.20.0/24"]
  database_subnet_cidrs = ["10.0.100.0/24", "10.0.200.0/24"]
  
  enable_nat_gateway = true
  enable_vpn_gateway = false
  enable_flow_logs   = true
  
  common_tags = var.common_tags
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| vpc_name | Name for the VPC | `string` | n/a | yes |
| vpc_cidr | CIDR block for the VPC | `string` | n/a | yes |
| public_subnet_cidrs | List of public subnet CIDR blocks | `list(string)` | n/a | yes |
| private_subnet_cidrs | List of private subnet CIDR blocks | `list(string)` | n/a | yes |
| database_subnet_cidrs | List of database subnet CIDR blocks | `list(string)` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| vpc_id | The VPC ID |
| vpc_cidr_block | The VPC CIDR block |
| public_subnet_ids | List of public subnet IDs |
| private_subnet_ids | List of private subnet IDs |
| database_subnet_ids | List of database subnet IDs |

## Security

- Network ACLs provide subnet-level security
- Security groups provide instance-level security
- VPC Flow Logs capture network traffic for monitoring
- Private subnets have no direct internet access
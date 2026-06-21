# Transit Gateway Module

AWS Transit Gateway for hub-and-spoke connectivity between all UK Landing Zone accounts and on-premises networks.

## Features

- Centralised Transit Gateway in the Network Hub Account
- VPC attachments: Security, Logging, Networking, Production-UK, Non-Production-UK, Sandbox
- Route tables: isolated per environment (Production, Non-Production, Shared)
- Blackhole routes to prevent environment cross-talk
- RAM sharing for cross-account attachment
- Flow log monitoring

## Network Ranges

| Environment | CIDR |
|-------------|------|
| Management | 10.10.0.0/16 |
| Security | 10.20.0.0/16 |
| Logging | 10.30.0.0/16 |
| Network Hub | 10.40.0.0/16 |
| Production-UK | 10.10.0.0/16 |
| Non-Production-UK | 10.50.0.0/16 |
| Sandbox | 10.100.0.0/16 |

## Usage

```hcl
module "transit_gateway" {
  source = "../../modules/networking/transit-gateway"

  amazon_side_asn         = 64512
  auto_accept_shared_attachments = true
  common_tags             = local.common_tags
}
```

## Compliance

- Requirement 8.1: Transit Gateway for centralised connectivity
- NCSC Principle 4: Separation between users

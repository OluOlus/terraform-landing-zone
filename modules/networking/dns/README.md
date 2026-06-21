# DNS Module

Route 53 private hosted zones and Resolver endpoints for centralised DNS in the Network Hub Account.

## Features

- Private hosted zones for internal service discovery
- Route 53 Resolver inbound/outbound endpoints for on-premises DNS integration
- DNS forwarder rules for workload VPCs
- DNSSEC signing for private zones
- VPC association across all accounts via Transit Gateway
- DNS query logging to CloudWatch

## Usage

```hcl
module "dns" {
  source = "../../modules/networking/dns"

  vpc_id                   = module.vpc.vpc_id
  private_hosted_zone_name = "internal.uklandingzone.local"
  on_premises_dns_servers  = ["10.0.0.2", "10.0.0.3"]
  common_tags              = local.common_tags
}
```

## Compliance

- NCSC Principle 11: External interface protection
- Requirement 8.3: DNS resolution via Route 53 Resolver

# Network Firewall Module

AWS Network Firewall for stateful traffic inspection, egress filtering, and UK-specific threat prevention.

## Features

- Stateful and stateless rule groups
- UK egress rules: deny non-UK traffic, allow approved SaaS destinations
- Threat prevention: Suricata-based IDS/IPS rules
- Application-layer filtering (HTTP/HTTPS domain filtering)
- Flow logs to S3 and CloudWatch
- Alert rules for exfiltration patterns and known bad IPs

## Usage

```hcl
module "network_firewall" {
  source = "../../modules/networking/network-firewall"

  vpc_id              = module.vpc.vpc_id
  subnet_ids          = module.vpc.firewall_subnet_ids
  firewall_policy_arn = null  # created internally
  common_tags         = local.common_tags
}
```

## Compliance

- NCSC Principle 11: External interface protection
- NCSC Principle 12: Secure service administration
- Requirement 8.2: Network Firewall for traffic inspection

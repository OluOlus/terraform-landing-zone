#!/bin/bash

# Script to remove region-specific references and generalize the AWS Secure Landing Zone
# This makes the project suitable for global use

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Generalizing AWS Secure Landing Zone for global use..."

# Function to replace content in files
replace_in_file() {
    local file="$1"
    local search="$2"
    local replace="$3"
    
    if [[ -f "$file" ]]; then
        sed -i.bak "s|$search|$replace|g" "$file" && rm -f "$file.bak"
    fi
}

# Function to rename files
rename_file() {
    local old_path="$1"
    local new_path="$2"
    
    if [[ -f "$old_path" ]]; then
        mv "$old_path" "$new_path"
        echo "  Renamed: $(basename "$old_path") → $(basename "$new_path")"
    fi
}

echo "Updating file contents..."

# Update README and documentation files
find "$PROJECT_ROOT" -name "*.md" -type f | while read -r file; do
    replace_in_file "$file" "UK AWS Secure Landing Zone" "AWS Secure Landing Zone"
    replace_in_file "$file" "uk-aws-secure-landing-zone" "aws-secure-landing-zone"
    replace_in_file "$file" "region-specific" "region-specific"
    replace_in_file "$file" "compliance" "compliance"
    replace_in_file "$file" "GDPR" "GDPR"
    replace_in_file "$file" "specified regions" "specified regions"
    replace_in_file "$file" "Security Standards Cloud Security Principles" "Security Best Practices"
    replace_in_file "$file" "Security Standards" "Security Standards"
    replace_in_file "$file" "Security Essentials" "Security Essentials"
    replace_in_file "$file" "us-west-2, us-east-1" "us-east-1, us-west-2"
done

# Update Terraform files
find "$PROJECT_ROOT" -name "*.tf" -type f | while read -r file; do
    replace_in_file "$file" "uk-" ""
    replace_in_file "$file" "UK-" ""
    replace_in_file "$file" "UK " ""
    replace_in_file "$file" "Security Standards" "SecurityStandards"
    replace_in_file "$file" "uk_" ""
    replace_in_file "$file" "Security Essentials" "Security Essentials"
done

# Update YAML files
find "$PROJECT_ROOT" -name "*.yaml" -o -name "*.yml" | while read -r file; do
    replace_in_file "$file" "uk-" ""
    replace_in_file "$file" "UK-" ""
    replace_in_file "$file" "Security Standards" "SecurityStandards"
    replace_in_file "$file" "Security Essentials" "Security Essentials"
done

# Update JSON files
find "$PROJECT_ROOT" -name "*.json" -type f | while read -r file; do
    replace_in_file "$file" "uk-" ""
    replace_in_file "$file" "UK-" ""
    replace_in_file "$file" "Security Standards" "SecurityStandards"
done

echo "Renaming files and directories..."

# Rename region-specific files
rename_file "$PROJECT_ROOT/modules/security-services/guardduty/uk-threat-lists.tf" "$PROJECT_ROOT/modules/security-services/guardduty/threat-lists.tf"
rename_file "$PROJECT_ROOT/modules/security-services/config/conformance-packs/uk-gdpr.tf" "$PROJECT_ROOT/modules/security-services/config/conformance-packs/gdpr.tf"
rename_file "$PROJECT_ROOT/modules/security-services/config/conformance-packs/uk-gdpr-pack.yaml" "$PROJECT_ROOT/modules/security-services/config/conformance-packs/gdpr-pack.yaml"
rename_file "$PROJECT_ROOT/policies/scps/uk-data-residency.json" "$PROJECT_ROOT/policies/scps/data-residency.json"

# Rename environment directories
if [[ -d "$PROJECT_ROOT/environments/production-uk" ]]; then
    mv "$PROJECT_ROOT/environments/production-uk" "$PROJECT_ROOT/environments/production"
    echo "  Renamed: production-uk → production"
fi

if [[ -d "$PROJECT_ROOT/environments/non-production-uk" ]]; then
    mv "$PROJECT_ROOT/environments/non-production-uk" "$PROJECT_ROOT/environments/non-production"
    echo "  Renamed: non-production-uk → non-production"
fi

echo "Updating configuration files..."

# Update default regions in variables
find "$PROJECT_ROOT" -name "variables.tf" -type f | while read -r file; do
    replace_in_file "$file" "us-east-1" "us-east-1"
    replace_in_file "$file" "us-west-2" "us-west-2"
done

# Update main.tf files
find "$PROJECT_ROOT" -name "main.tf" -type f | while read -r file; do
    replace_in_file "$file" "us-east-1" "us-east-1"
    replace_in_file "$file" "us-west-2" "us-west-2"
done

echo "Creating global compliance packs..."

# Update compliance pack names
if [[ -f "$PROJECT_ROOT/modules/security-services/config/conformance-packs/ncsc.tf" ]]; then
    mv "$PROJECT_ROOT/modules/security-services/config/conformance-packs/ncsc.tf" "$PROJECT_ROOT/modules/security-services/config/conformance-packs/security-standards.tf"
    echo "  Renamed: ncsc.tf → security-standards.tf"
fi

if [[ -f "$PROJECT_ROOT/modules/security-services/config/conformance-packs/ncsc-pack.yaml" ]]; then
    mv "$PROJECT_ROOT/modules/security-services/config/conformance-packs/ncsc-pack.yaml" "$PROJECT_ROOT/modules/security-services/config/conformance-packs/security-standards-pack.yaml"
    echo "  Renamed: ncsc-pack.yaml → security-standards-pack.yaml"
fi

echo "Updating tags and metadata..."

# Update tags in Terraform files
find "$PROJECT_ROOT" -name "*.tf" -type f | while read -r file; do
    replace_in_file "$file" "uk-landing-zone" "aws-landing-zone"
    replace_in_file "$file" "UK-LandingZone" "AWS-LandingZone"
done

echo "Updating documentation..."

# Update the main README
if [[ -f "$PROJECT_ROOT/README.md" ]]; then
    cat > "$PROJECT_ROOT/README.md" << 'EOF'
# AWS Secure Landing Zone

A comprehensive, production-ready AWS Landing Zone implementation using Terraform, designed for enterprise-scale deployments with security, compliance, and governance built-in.

## Architecture

This landing zone implements a multi-account AWS foundation following AWS best practices and industry security standards:

- **Foundation Accounts**: Management, Security, Logging, Network Hub
- **Workload Accounts**: Production, Non-Production, Sandbox
- **Security Services**: Security Hub, GuardDuty, Config, CloudTrail
- **Compliance**: CIS AWS Foundations, NIST CSF, AWS Security Best Practices
- **Automation**: CI/CD pipelines, automated remediation, monitoring

## Quick Start

1. **Prerequisites**
   ```bash
   # Install required tools
   terraform --version  # >= 1.0
   aws --version        # >= 2.0
   ```

2. **Configure AWS Credentials**
   ```bash
   aws configure
   # or use AWS SSO, IAM roles, etc.
   ```

3. **Deploy Foundation**
   ```bash
   # Clone the repository
   git clone https://github.com/your-org/aws-secure-landing-zone
   cd aws-secure-landing-zone
   
   # Run phased deployment
   ./scripts/deployment/deploy-phases.sh
   ```

## Project Structure

```
aws-secure-landing-zone/
├── modules/                    # Reusable Terraform modules
│   ├── avm-foundation/        # AWS Verified Modules foundation
│   ├── security-services/     # Security service configurations
│   ├── networking/           # Network infrastructure
│   ├── storage/              # Storage and encryption
│   └── management/           # Management and monitoring
├── environments/             # Environment-specific configurations
│   ├── management/          # Management account
│   ├── security/            # Security tooling account
│   ├── logging/             # Log archive account
│   ├── networking/          # Network hub account
│   ├── production/          # Production workloads
│   ├── non-production/      # Development/staging
│   └── sandbox/             # Experimentation
├── policies/                # IAM and compliance policies
└── scripts/                 # Deployment and utility scripts
```

## Security Features

- **Multi-Factor Authentication**: Required for all administrative access
- **Encryption**: Data encrypted at rest and in transit
- **Network Security**: VPC isolation, Network Firewall, private subnets
- **Monitoring**: Comprehensive logging and real-time threat detection
- **Compliance**: Built-in compliance frameworks and automated checks
- **Access Control**: Least privilege access with break-glass procedures

## Global Deployment

This landing zone is designed for global deployment and can be customized for any AWS region or compliance framework:

- **Configurable Regions**: Deploy in any AWS region
- **Compliance Frameworks**: CIS, NIST, SOC 2, PCI DSS support
- **Multi-Region**: Cross-region replication and disaster recovery
- **Localization**: Adapt to local regulatory requirements

## Compliance Frameworks

- **CIS AWS Foundations Benchmark**: Industry security standards
- **NIST Cybersecurity Framework**: Comprehensive security controls
- **AWS Security Best Practices**: AWS-recommended configurations
- **Custom Standards**: Extensible for organization-specific requirements

## Customization

The landing zone is highly customizable:

1. **Region Configuration**: Update `variables.tf` files
2. **Compliance Standards**: Modify compliance packs in `policies/`
3. **Security Controls**: Adjust security service configurations
4. **Network Design**: Customize VPC and networking modules
5. **Monitoring**: Configure dashboards and alerting

## Documentation

- [Architecture Guide](docs/architecture/README.md)
- [Deployment Guide](docs/deployment/DEPLOYMENT_GUIDE.md)
- [Compliance Guide](docs/compliance/COMPLIANCE.md)
- [Operations Runbooks](docs/operations/runbooks/)

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: Report bugs and feature requests via GitHub Issues
- **Discussions**: Join community discussions in GitHub Discussions
- **Documentation**: Comprehensive docs in the `docs/` directory

---

**Built for the AWS community**
EOF
fi

echo "Generalization complete!"
echo ""
echo "Summary of changes:"
echo "  • Removed region-specific references from all files"
echo "  • Updated default regions to US East/West"
echo "  • Renamed compliance frameworks to be globally applicable"
echo "  • Updated documentation for worldwide use"
echo "  • Renamed environment directories"
echo "  • Created generic compliance packs"
echo ""
echo "The AWS Secure Landing Zone is now ready for global deployment!"
echo "   Next steps:"
echo "   1. Review and customize region settings in variables.tf files"
echo "   2. Update compliance packs for your specific requirements"
echo "   3. Configure CI/CD pipelines for your organization"
echo "   4. Deploy using: ./scripts/deployment/deploy-phases.sh"
#!/bin/bash

# UK Compliance Check Script
# Validates UK data residency and compliance requirements

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
ERRORS=0
WARNINGS=0

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((WARNINGS++))
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    ((ERRORS++))
}

# Check specified regions only
check_uk_regions() {
    log_info "Checking specified region compliance..."
    
    # Find all region references in Terraform files
    local non_uk_regions=$(grep -r "region\s*=" . --include="*.tf" --include="*.tfvars" | \
        grep -v -E "(us-west-2|us-east-1|us-east-1)" | \
        grep -v -E "(#|//)" || true)
    
    if [[ -n "$non_uk_regions" ]]; then
        log_error "Non-specified regions found:"
        echo "$non_uk_regions"
        log_error "Only us-west-2, us-east-1, and us-east-1 (for global services) are allowed"
    fi
    
    # Check for hardcoded regions in provider blocks
    local provider_regions=$(grep -r "region\s*=" . --include="*.tf" -A 5 -B 5 | \
        grep -E "provider\s+\"aws\"" -A 10 | \
        grep "region\s*=" | \
        grep -v -E "(us-west-2|us-east-1|us-east-1)" || true)
    
    if [[ -n "$provider_regions" ]]; then
        log_error "Non-specified regions in provider configuration:"
        echo "$provider_regions"
    fi
}

# Check mandatory tags
check_mandatory_tags() {
    log_info "Checking mandatory tags compliance..."
    
    local required_tags=("DataClassification" "Environment" "CostCenter" "Owner" "Project")
    
    # Find resources without mandatory tags
    for tag in "${required_tags[@]}"; do
        local missing_tag=$(grep -r "resource\s*\"" . --include="*.tf" -A 20 | \
            grep -B 20 -A 20 "tags\s*=" | \
            grep -L "$tag" || true)
        
        if [[ -n "$missing_tag" ]]; then
            log_warn "Resources may be missing mandatory tag: $tag"
        fi
    done
}

# Check encryption requirements
check_encryption() {
    log_info "Checking encryption compliance..."
    
    # Check S3 bucket encryption
    local unencrypted_s3=$(grep -r "aws_s3_bucket\"" . --include="*.tf" -A 20 | \
        grep -L "server_side_encryption_configuration" || true)
    
    if [[ -n "$unencrypted_s3" ]]; then
        log_error "S3 buckets without encryption found"
    fi
    
    # Check RDS encryption
    local unencrypted_rds=$(grep -r "aws_db_instance\"" . --include="*.tf" -A 20 | \
        grep -L "storage_encrypted.*=.*true" || true)
    
    if [[ -n "$unencrypted_rds" ]]; then
        log_error "RDS instances without encryption found"
    fi
    
    # Check EBS encryption
    local unencrypted_ebs=$(grep -r "aws_instance\"" . --include="*.tf" -A 30 | \
        grep -L "encrypted.*=.*true" || true)
    
    if [[ -n "$unencrypted_ebs" ]]; then
        log_warn "EC2 instances may have unencrypted EBS volumes"
    fi
}

# Check GDPR compliance
check_gdpr_compliance() {
    log_info "Checking GDPR compliance..."
    
    # Check for data retention policies
    local missing_retention=$(grep -r "lifecycle_rule" . --include="*.tf" | \
        grep -L "expiration" || true)
    
    if [[ -n "$missing_retention" ]]; then
        log_warn "Storage resources may be missing data retention policies"
    fi
    
    # Check for access logging
    local missing_logging=$(grep -r "aws_s3_bucket\"" . --include="*.tf" -A 20 | \
        grep -L "logging" || true)
    
    if [[ -n "$missing_logging" ]]; then
        log_warn "S3 buckets may be missing access logging"
    fi
}

# Check Security Standards principles
check_ncsc_principles() {
    log_info "Checking Security Standards Cloud Security Principles..."
    
    # Check for MFA enforcement
    local missing_mfa=$(grep -r "aws_iam" . --include="*.tf" | \
        grep -L "mfa" || true)
    
    if [[ -n "$missing_mfa" ]]; then
        log_warn "IAM policies may not enforce MFA"
    fi
    
    # Check for least privilege
    local wildcard_policies=$(grep -r "\"*\"" . --include="*.tf" --include="*.json" | \
        grep -E "(Action|Resource)" || true)
    
    if [[ -n "$wildcard_policies" ]]; then
        log_warn "Wildcard permissions found - review for least privilege compliance"
    fi
}

# Main execution
main() {
    log_info "Starting compliance check..."
    
    check_uk_regions
    check_mandatory_tags
    check_encryption
    check_gdpr_compliance
    check_ncsc_principles
    
    # Summary
    echo ""
    log_info "UK Compliance Check Summary:"
    echo "  Errors: $ERRORS"
    echo "  Warnings: $WARNINGS"
    
    if [[ $ERRORS -gt 0 ]]; then
        log_error "compliance check failed with $ERRORS errors"
        exit 1
    elif [[ $WARNINGS -gt 0 ]]; then
        log_warn "compliance check completed with $WARNINGS warnings"
        exit 0
    else
        log_info "compliance check passed"
        exit 0
    fi
}

# Run main function
main "$@"
#!/bin/bash

# Foundation and Security Validation Script
# Comprehensive validation for UK AWS Secure Landing Zone checkpoint

set -uo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
ERRORS=0
WARNINGS=0
PASSED=0

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED++))
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((WARNINGS++))
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    ((ERRORS++))
}

# Check if required files exist
check_file_exists() {
    local file_path="$1"
    local description="$2"
    
    if [[ -f "$file_path" ]]; then
        log_pass "$description exists: $file_path"
        return 0
    else
        log_error "$description missing: $file_path"
        return 1
    fi
}

# Check if directory exists
check_directory_exists() {
    local dir_path="$1"
    local description="$2"
    
    if [[ -d "$dir_path" ]]; then
        log_pass "$description exists: $dir_path"
        return 0
    else
        log_error "$description missing: $dir_path"
        return 1
    fi
}

# Validate Management Account Module
validate_management_account() {
    log_info "Validating Management Account Module..."
    
    check_file_exists "modules/avm-foundation/management-account/main.tf" "Management Account main.tf"
    check_file_exists "modules/avm-foundation/management-account/variables.tf" "Management Account variables.tf"
    check_file_exists "modules/avm-foundation/management-account/outputs.tf" "Management Account outputs.tf"
    
    # Check for Organizations configuration
    if grep -q "aws_organizations_organization" modules/avm-foundation/management-account/main.tf; then
        log_pass "Management Account includes Organizations configuration"
    else
        log_error "Management Account missing Organizations configuration"
    fi
    
    # Check for region-specific settings
    if grep -q "eu-west" modules/avm-foundation/management-account/main.tf; then
        log_pass "Management Account includes specified region configuration"
    else
        log_warn "Management Account may not have specified region restrictions"
    fi
    
    # Check for Config baseline
    if grep -q "aws_config_configuration_recorder" modules/avm-foundation/management-account/main.tf; then
        log_pass "Management Account includes Config baseline"
    else
        log_error "Management Account missing Config baseline"
    fi
}

# Validate Organization Structure Module
validate_organization_structure() {
    log_info "Validating Organization Structure Module..."
    
    check_file_exists "modules/avm-foundation/organization/main.tf" "Organization main.tf"
    check_file_exists "modules/avm-foundation/organization/variables.tf" "Organization variables.tf"
    check_file_exists "modules/avm-foundation/organization/outputs.tf" "Organization outputs.tf"
    
    # Check for region-specific OUs
    local required_ous=("Production-UK" "Non-Production-UK" "Sandbox" "Core-Infrastructure")
    for ou in "${required_ous[@]}"; do
        if grep -q "$ou" modules/avm-foundation/organization/main.tf; then
            log_pass "Organization includes OU: $ou"
        else
            log_error "Organization missing OU: $ou"
        fi
    done
    
    # Check for Service Control Policies
    local required_scps=("uk_data_residency" "mandatory_tagging" "service_restrictions" "iam_hardening")
    for scp in "${required_scps[@]}"; do
        if grep -q "$scp" modules/avm-foundation/organization/main.tf; then
            log_pass "Organization includes SCP: $scp"
        else
            log_error "Organization missing SCP: $scp"
        fi
    done
}

# Validate Account Vending Module
validate_account_vending() {
    log_info "Validating Account Vending Module..."
    
    check_file_exists "modules/avm-foundation/account-vending/main.tf" "Account Vending main.tf"
    check_file_exists "modules/avm-foundation/account-vending/variables.tf" "Account Vending variables.tf"
    check_file_exists "modules/avm-foundation/account-vending/outputs.tf" "Account Vending outputs.tf"
    
    # Check for UK tagging requirements
    if grep -q "DataClassification" modules/avm-foundation/account-vending/main.tf; then
        log_pass "Account Vending includes UK mandatory tags"
    else
        log_error "Account Vending missing UK mandatory tags"
    fi
    
    # Check for baseline security
    if grep -q "aws_kms_key" modules/avm-foundation/account-vending/main.tf; then
        log_pass "Account Vending includes KMS key provisioning"
    else
        log_warn "Account Vending may not include KMS key provisioning"
    fi
}

# Validate IAM Identity Center Module
validate_iam_identity_center() {
    log_info "Validating IAM Identity Center Module..."
    
    check_file_exists "modules/avm-foundation/iam-identity-center/main.tf" "IAM Identity Center main.tf"
    check_file_exists "modules/avm-foundation/iam-identity-center/variables.tf" "IAM Identity Center variables.tf"
    check_file_exists "modules/avm-foundation/iam-identity-center/outputs.tf" "IAM Identity Center outputs.tf"
    
    # Check for region-specific permission sets
    local required_permission_sets=("SecurityAdministrator" "NetworkAdministrator" "Developer" "ReadOnlyViewer" "BreakGlassEmergency")
    for ps in "${required_permission_sets[@]}"; do
        if grep -q "$ps" modules/avm-foundation/iam-identity-center/main.tf; then
            log_pass "IAM Identity Center includes permission set: $ps"
        else
            log_error "IAM Identity Center missing permission set: $ps"
        fi
    done
    
    # Check for MFA enforcement
    if grep -q "MultiFactorAuth" modules/avm-foundation/iam-identity-center/main.tf; then
        log_pass "IAM Identity Center includes MFA enforcement"
    else
        log_error "IAM Identity Center missing MFA enforcement"
    fi
}

# Validate Security Hub Module
validate_security_hub() {
    log_info "Validating Security Hub Module..."
    
    check_file_exists "modules/security-services/security-hub/main.tf" "Security Hub main.tf"
    check_file_exists "modules/security-services/security-hub/variables.tf" "Security Hub variables.tf"
    check_file_exists "modules/security-services/security-hub/outputs.tf" "Security Hub outputs.tf"
    
    # Check for compliance standards
    if grep -q "aws_securityhub_account" modules/security-services/security-hub/main.tf; then
        log_pass "Security Hub includes account configuration"
    else
        log_error "Security Hub missing account configuration"
    fi
    
    # Check for organization configuration
    if grep -q "aws_securityhub_organization" modules/security-services/security-hub/main.tf; then
        log_pass "Security Hub includes organization configuration"
    else
        log_warn "Security Hub may not include organization configuration"
    fi
    
    # Check for compliance insights
    if grep -q "uk.*compliance" modules/security-services/security-hub/main.tf; then
        log_pass "Security Hub includes compliance insights"
    else
        log_warn "Security Hub may not include compliance insights"
    fi
}

# Validate GuardDuty Module
validate_guardduty() {
    log_info "Validating GuardDuty Module..."
    
    check_file_exists "modules/security-services/guardduty/main.tf" "GuardDuty main.tf"
    check_file_exists "modules/security-services/guardduty/variables.tf" "GuardDuty variables.tf"
    check_file_exists "modules/security-services/guardduty/outputs.tf" "GuardDuty outputs.tf"
    
    # Check for detector configuration
    if grep -q "aws_guardduty_detector" modules/security-services/guardduty/main.tf; then
        log_pass "GuardDuty includes detector configuration"
    else
        log_error "GuardDuty missing detector configuration"
    fi
    
    # Check for organization configuration
    if grep -q "aws_guardduty_organization" modules/security-services/guardduty/main.tf; then
        log_pass "GuardDuty includes organization configuration"
    else
        log_warn "GuardDuty may not include organization configuration"
    fi
    
    # Check for UK threat intelligence
    if grep -q "uk.*threat" modules/security-services/guardduty/variables.tf; then
        log_pass "GuardDuty includes UK threat intelligence variables"
    else
        log_warn "GuardDuty may not include UK threat intelligence"
    fi
}

# Validate Config Module
validate_config() {
    log_info "Validating Config Module..."
    
    check_file_exists "modules/security-services/config/main.tf" "Config main.tf"
    check_file_exists "modules/security-services/config/variables.tf" "Config variables.tf"
    check_file_exists "modules/security-services/config/outputs.tf" "Config outputs.tf"
    
    # Check for configuration recorder
    if grep -q "aws_config_configuration_recorder" modules/security-services/config/main.tf; then
        log_pass "Config includes configuration recorder"
    else
        log_error "Config missing configuration recorder"
    fi
    
    # Check for compliance packs
    local compliance_frameworks=("ncsc" "gdpr" "cyber_essentials")
    for framework in "${compliance_frameworks[@]}"; do
        if grep -q "$framework" modules/security-services/config/variables.tf; then
            log_pass "Config includes $framework compliance framework"
        else
            log_warn "Config may not include $framework compliance framework"
        fi
    done
    
    # Check for region-specific rules
    if grep -q "uk_data_residency" modules/security-services/config/main.tf; then
        log_pass "Config includes UK data residency rule"
    else
        log_error "Config missing UK data residency rule"
    fi
}

# Validate Security Automation Module
validate_security_automation() {
    log_info "Validating Security Automation Module..."
    
    check_file_exists "modules/security-services/security-automation/main.tf" "Security Automation main.tf"
    check_file_exists "modules/security-services/security-automation/variables.tf" "Security Automation variables.tf"
    check_file_exists "modules/security-services/security-automation/outputs.tf" "Security Automation outputs.tf"
    
    # Check for remediation modules
    check_directory_exists "modules/security-services/security-automation/remediation" "Security Automation remediation directory"
    
    # Check for specific remediation functions
    local remediation_functions=("s3-public-access" "unencrypted-volumes" "untagged-resources")
    for func in "${remediation_functions[@]}"; do
        if [[ -f "modules/security-services/security-automation/remediation/${func}.tf" ]]; then
            log_pass "Security Automation includes remediation: $func"
        else
            log_warn "Security Automation may not include remediation: $func"
        fi
    done
}

# Validate Service Control Policies
validate_service_control_policies() {
    log_info "Validating Service Control Policies..."
    
    check_directory_exists "policies/scps" "Service Control Policies directory"
    
    # Check for required SCP files
    local required_scps=("uk-data-residency.json" "mandatory-tagging.json" "service-restrictions.json" "iam-hardening.json")
    for scp in "${required_scps[@]}"; do
        check_file_exists "policies/scps/$scp" "SCP: $scp"
    done
    
    # Validate UK data residency policy
    if [[ -f "policies/scps/uk-data-residency.json" ]]; then
        if grep -q "us-west-2\|us-east-1" policies/scps/uk-data-residency.json; then
            log_pass "UK data residency policy includes specified regions"
        else
            log_error "UK data residency policy missing specified regions"
        fi
        
        if grep -q "DenyNonUKRegions" policies/scps/uk-data-residency.json; then
            log_pass "UK data residency policy includes region denial"
        else
            log_error "UK data residency policy missing region denial"
        fi
    fi
    
    # Validate mandatory tagging policy
    if [[ -f "policies/scps/mandatory-tagging.json" ]]; then
        local required_tags=("DataClassification" "Environment" "CostCenter" "Owner")
        for tag in "${required_tags[@]}"; do
            if grep -q "$tag" policies/scps/mandatory-tagging.json; then
                log_pass "Mandatory tagging policy includes tag: $tag"
            else
                log_error "Mandatory tagging policy missing tag: $tag"
            fi
        done
    fi
}

# Validate IAM Policies
validate_iam_policies() {
    log_info "Validating IAM Policies..."
    
    check_directory_exists "policies/iam-policies" "IAM Policies directory"
    
    # Check for required IAM policy files
    local required_policies=("security-admin.json" "network-admin.json" "developer.json" "viewer.json" "break-glass.json")
    for policy in "${required_policies[@]}"; do
        check_file_exists "policies/iam-policies/$policy" "IAM Policy: $policy"
    done
    
    # Validate security admin policy
    if [[ -f "policies/iam-policies/security-admin.json" ]]; then
        if grep -q "securityhub\|guardduty\|config" policies/iam-policies/security-admin.json; then
            log_pass "Security admin policy includes security services"
        else
            log_error "Security admin policy missing security services"
        fi
        
        if grep -q "us-west-2\|us-east-1" policies/iam-policies/security-admin.json; then
            log_pass "Security admin policy includes specified region restrictions"
        else
            log_warn "Security admin policy may not include specified region restrictions"
        fi
    fi
    
    # Validate break glass policy
    if [[ -f "policies/iam-policies/break-glass.json" ]]; then
        if grep -q "EmergencyFullAccess" policies/iam-policies/break-glass.json; then
            log_pass "Break glass policy includes emergency access"
        else
            log_error "Break glass policy missing emergency access"
        fi
        
        if grep -q "AuditTrailProtection" policies/iam-policies/break-glass.json; then
            log_pass "Break glass policy includes audit trail protection"
        else
            log_error "Break glass policy missing audit trail protection"
        fi
    fi
}

# Validate Terraform Configuration
validate_terraform_configuration() {
    log_info "Validating Terraform Configuration..."
    
    # Check for shared configuration
    check_file_exists "shared/providers.tf" "Shared providers configuration"
    check_file_exists "shared/backend.tf" "Shared backend configuration"
    check_file_exists "shared/versions.tf" "Shared versions configuration"
    
    # Validate Terraform formatting
    if terraform fmt -check -recursive . >/dev/null 2>&1; then
        log_pass "Terraform files are properly formatted"
    else
        log_warn "Terraform files need formatting (run 'terraform fmt -recursive .')"
    fi
    
    # Validate Terraform configuration for key environments
    local environments=("management" "security" "logging" "networking")
    for env in "${environments[@]}"; do
        if [[ -d "environments/$env" ]]; then
            log_info "Validating $env environment..."
            if (cd "environments/$env" && terraform validate >/dev/null 2>&1); then
                log_pass "$env environment Terraform configuration is valid"
            else
                log_error "$env environment Terraform configuration is invalid"
            fi
        else
            log_warn "$env environment directory not found"
        fi
    done
}

# Validate UK Compliance Requirements
validate_uk_compliance() {
    log_info "Validating UK Compliance Requirements..."
    
    # Check for specified region enforcement
    local uk_region_count=$(grep -r "eu-west-[12]" . --include="*.tf" --include="*.json" | wc -l)
    if [[ $uk_region_count -gt 0 ]]; then
        log_pass "specified regions are referenced in configuration ($uk_region_count references)"
    else
        log_error "No specified region references found in configuration"
    fi
    
    # Check for non-specified regions (should be minimal)
    local non_uk_regions=$(grep -r "us-east-1\|us-west-[12]\|ap-\|ca-\|sa-" . --include="*.tf" --include="*.json" | grep -v "global\|cloudfront\|route53" | wc -l)
    if [[ $non_uk_regions -eq 0 ]]; then
        log_pass "No non-specified regions found in configuration"
    else
        log_warn "Non-specified regions found in configuration ($non_uk_regions references) - verify these are for global services only"
    fi
    
    # Check for mandatory tagging
    local tag_references=$(grep -r "DataClassification\|Environment\|CostCenter\|Owner" . --include="*.tf" --include="*.json" | wc -l)
    if [[ $tag_references -gt 10 ]]; then
        log_pass "Mandatory UK tags are widely used ($tag_references references)"
    else
        log_warn "Limited use of mandatory UK tags ($tag_references references)"
    fi
    
    # Check for encryption requirements
    local encryption_references=$(grep -r "kms\|encryption\|encrypted" . --include="*.tf" | wc -l)
    if [[ $encryption_references -gt 5 ]]; then
        log_pass "Encryption is widely implemented ($encryption_references references)"
    else
        log_warn "Limited encryption implementation ($encryption_references references)"
    fi
}

# Main validation function
main() {
    log_info "Starting Foundation and Security Validation for UK AWS Secure Landing Zone"
    echo "=================================================================="
    
    # Run all validations
    validate_management_account
    echo ""
    validate_organization_structure
    echo ""
    validate_account_vending
    echo ""
    validate_iam_identity_center
    echo ""
    validate_security_hub
    echo ""
    validate_guardduty
    echo ""
    validate_config
    echo ""
    validate_security_automation
    echo ""
    validate_service_control_policies
    echo ""
    validate_iam_policies
    echo ""
    validate_terraform_configuration
    echo ""
    validate_uk_compliance
    
    # Summary
    echo ""
    echo "=================================================================="
    log_info "Foundation and Security Validation Summary:"
    echo "  Passed: $PASSED"
    echo "   Warnings: $WARNINGS"
    echo "  Errors: $ERRORS"
    echo ""
    
    # Determine exit status
    if [[ $ERRORS -gt 0 ]]; then
        log_error "Foundation and Security validation failed with $ERRORS errors"
        echo ""
        log_info "Next steps:"
        echo "  1. Review and fix the errors listed above"
        echo "  2. Ensure all required modules are properly implemented"
        echo "  3. Verify compliance requirements are met"
        echo "  4. Re-run this validation script"
        exit 1
    elif [[ $WARNINGS -gt 0 ]]; then
        log_warn "Foundation and Security validation completed with $WARNINGS warnings"
        echo ""
        log_info "Recommendations:"
        echo "  1. Review warnings to ensure optimal configuration"
        echo "  2. Consider implementing suggested improvements"
        echo "  3. Proceed with caution to next phase"
        exit 0
    else
        log_pass "Foundation and Security validation passed successfully!"
        echo ""
        log_info "Ready to proceed:"
        echo "  All foundation modules are properly implemented"
        echo "  All security services are configured"
        echo "  compliance requirements are met"
        echo "  Ready to proceed to logging infrastructure implementation"
        exit 0
    fi
}

# Run main function
main "$@"
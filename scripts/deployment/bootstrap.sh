#!/bin/bash

# UK AWS Secure Landing Zone Bootstrap Script
# This script sets up the initial Terraform state management infrastructure

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed"
        exit 1
    fi
    
    # Check Terraform
    if ! command -v terraform &> /dev/null; then
        log_error "Terraform is not installed"
        exit 1
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials are not configured"
        exit 1
    fi
    
    # Check region is UK
    if [[ "$REGION" != "us-west-2" && "$REGION" != "us-east-1" ]]; then
        log_error "Region must be us-west-2 or us-east-1 for UK data residency compliance"
        exit 1
    fi
    
    log_info "Prerequisites check passed"
}

# Create S3 bucket for Terraform state
create_state_bucket() {
    local bucket_name="uk-landing-zone-terraform-state-${ACCOUNT_ID}"
    
    log_info "Creating Terraform state bucket: ${bucket_name}"
    
    # Create bucket
    if aws s3api head-bucket --bucket "${bucket_name}" 2>/dev/null; then
        log_warn "Bucket ${bucket_name} already exists"
    else
        aws s3api create-bucket \
            --bucket "${bucket_name}" \
            --region "${REGION}" \
            --create-bucket-configuration LocationConstraint="${REGION}"
    fi
    
    # Enable versioning
    aws s3api put-bucket-versioning \
        --bucket "${bucket_name}" \
        --versioning-configuration Status=Enabled
    
    # Enable encryption
    aws s3api put-bucket-encryption \
        --bucket "${bucket_name}" \
        --server-side-encryption-configuration '{
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyID": "alias/terraform-state-key"
                    }
                }
            ]
        }'
    
    # Block public access
    aws s3api put-public-access-block \
        --bucket "${bucket_name}" \
        --public-access-block-configuration \
        BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
    
    log_info "State bucket created and configured"
}

# Create DynamoDB table for state locking
create_lock_table() {
    local table_name="uk-landing-zone-terraform-locks"
    
    log_info "Creating DynamoDB table for state locking: ${table_name}"
    
    # Check if table exists
    if aws dynamodb describe-table --table-name "${table_name}" &>/dev/null; then
        log_warn "Table ${table_name} already exists"
    else
        aws dynamodb create-table \
            --table-name "${table_name}" \
            --attribute-definitions AttributeName=LockID,AttributeType=S \
            --key-schema AttributeName=LockID,KeyType=HASH \
            --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 \
            --region "${REGION}"
        
        # Wait for table to be active
        aws dynamodb wait table-exists --table-name "${table_name}"
    fi
    
    log_info "Lock table created"
}

# Create KMS key for encryption
create_kms_key() {
    local key_alias="alias/terraform-state-key"
    
    log_info "Creating KMS key for Terraform state encryption"
    
    # Check if key exists
    if aws kms describe-key --key-id "${key_alias}" &>/dev/null; then
        log_warn "KMS key ${key_alias} already exists"
    else
        local key_id=$(aws kms create-key \
            --description "KMS key for UK Landing Zone Terraform state encryption" \
            --key-usage ENCRYPT_DECRYPT \
            --key-spec SYMMETRIC_DEFAULT \
            --query 'KeyMetadata.KeyId' \
            --output text)
        
        # Create alias
        aws kms create-alias \
            --alias-name "terraform-state-key" \
            --target-key-id "${key_id}"
    fi
    
    log_info "KMS key created"
}

# Generate backend configuration files
generate_backend_configs() {
    log_info "Generating backend configuration files"
    
    local bucket_name="uk-landing-zone-terraform-state-${ACCOUNT_ID}"
    local table_name="uk-landing-zone-terraform-locks"
    
    # Create backend config directory
    mkdir -p "${PROJECT_ROOT}/backend-configs"
    
    # Generate backend config for each environment
    for env in management security logging networking production-uk non-production-uk sandbox; do
        cat > "${PROJECT_ROOT}/backend-configs/${env}.hcl" << EOF
bucket         = "${bucket_name}"
key            = "environments/${env}/terraform.tfstate"
region         = "${REGION}"
dynamodb_table = "${table_name}"
encrypt        = true
kms_key_id     = "alias/terraform-state-key"
EOF
    done
    
    log_info "Backend configuration files generated"
}

# Main execution
main() {
    log_info "Starting UK AWS Secure Landing Zone bootstrap process"
    
    check_prerequisites
    create_kms_key
    create_state_bucket
    create_lock_table
    generate_backend_configs
    
    log_info "Bootstrap process completed successfully!"
    log_info "You can now run: terraform init -backend-config=backend-configs/management.hcl"
}

# Run main function
main "$@"
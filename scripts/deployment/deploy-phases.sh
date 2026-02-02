#!/bin/bash

# AWS Secure Landing Zone - Phased Deployment Script
# This script deploys the landing zone in phases to ensure proper dependency management

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOG_FILE="$PROJECT_ROOT/deployment.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if terraform is installed
    if ! command -v terraform &> /dev/null; then
        error "Terraform is not installed. Please install Terraform first."
    fi
    
    # Check if AWS CLI is installed
    if ! command -v aws &> /dev/null; then
        error "AWS CLI is not installed. Please install AWS CLI first."
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        error "AWS credentials not configured. Please configure AWS credentials first."
    fi
    
    success "Prerequisites check passed"
}

# Deploy a specific environment
deploy_environment() {
    local env_name=$1
    local env_path="$PROJECT_ROOT/environments/$env_name"
    
    if [ ! -d "$env_path" ]; then
        error "Environment directory not found: $env_path"
    fi
    
    log "Deploying environment: $env_name"
    
    cd "$env_path"
    
    # Initialize Terraform
    log "Initializing Terraform for $env_name..."
    terraform init
    
    # Plan deployment
    log "Planning deployment for $env_name..."
    terraform plan -out="$env_name.tfplan"
    
    # Apply deployment
    log "Applying deployment for $env_name..."
    terraform apply "$env_name.tfplan"
    
    # Clean up plan file
    rm -f "$env_name.tfplan"
    
    success "Environment $env_name deployed successfully"
}

# Validate deployment
validate_deployment() {
    local env_name=$1
    local env_path="$PROJECT_ROOT/environments/$env_name"
    
    log "Validating deployment for $env_name..."
    
    cd "$env_path"
    
    # Run terraform validate
    terraform validate
    
    # Run terraform plan to check for drift
    terraform plan -detailed-exitcode
    
    success "Validation passed for $env_name"
}

# Main deployment function
main() {
    log "Starting AWS Secure Landing Zone phased deployment..."
    
    # Check prerequisites
    check_prerequisites
    
    # Phase 1: Management Account (Foundation)
    log "=== PHASE 1: Management Account Foundation ==="
    deploy_environment "management"
    validate_deployment "management"
    
    # Wait for Organizations to stabilize
    log "Waiting for AWS Organizations to stabilize..."
    sleep 30
    
    # Phase 2: Security Tooling Account
    log "=== PHASE 2: Security Tooling Account ==="
    deploy_environment "security"
    validate_deployment "security"
    
    # Phase 3: Log Archive Account
    log "=== PHASE 3: Log Archive Account ==="
    deploy_environment "logging"
    validate_deployment "logging"
    
    # Phase 4: Network Hub Account
    log "=== PHASE 4: Network Hub Account ==="
    deploy_environment "networking"
    validate_deployment "networking"
    
    # Phase 5: Production Workload Environment
    log "=== PHASE 5: Production Environment ==="
    deploy_environment "production"
    validate_deployment "production"
    
    # Phase 6: Non-Production Environment
    log "=== PHASE 6: Non-Production Environment ==="
    deploy_environment "non-production"
    validate_deployment "non-production"
    
    # Phase 7: Sandbox Environment
    log "=== PHASE 7: Sandbox Environment ==="
    deploy_environment "sandbox"
    validate_deployment "sandbox"
    
    success "AWS Secure Landing Zone deployment completed successfully!"
    
    # Display summary
    log "=== DEPLOYMENT SUMMARY ==="
    log "All environments have been deployed successfully:"
    log "  ✓ Management Account (Foundation)"
    log "  ✓ Security Tooling Account"
    log "  ✓ Log Archive Account"
    log "  ✓ Network Hub Account"
    log "  ✓ Production Environment"
    log "  ✓ Non-Production Environment"
    log "  ✓ Sandbox Environment"
    log ""
    log "Next steps:"
    log "1. Review the deployment outputs"
    log "2. Configure additional security settings as needed"
    log "3. Set up monitoring and alerting"
    log "4. Begin workload migration"
    log ""
    log "For troubleshooting, check the deployment log: $LOG_FILE"
}

# Handle script arguments
case "${1:-}" in
    "management"|"security"|"logging"|"networking"|"production"|"non-production"|"sandbox")
        log "Deploying single environment: $1"
        check_prerequisites
        deploy_environment "$1"
        validate_deployment "$1"
        ;;
    "validate")
        if [ -n "$2" ]; then
            validate_deployment "$2"
        else
            error "Please specify an environment to validate"
        fi
        ;;
    "help"|"-h"|"--help")
        echo "AWS Secure Landing Zone - Phased Deployment Script"
        echo ""
        echo "Usage:"
        echo "  $0                    # Deploy all environments in phases"
        echo "  $0 <environment>      # Deploy specific environment"
        echo "  $0 validate <env>     # Validate specific environment"
        echo "  $0 help              # Show this help"
        echo ""
        echo "Available environments:"
        echo "  management, security, logging, networking, production, non-production, sandbox"
        ;;
    "")
        main
        ;;
    *)
        error "Unknown command: $1. Use '$0 help' for usage information."
        ;;
esac
#!/bin/bash

# Test script for Organization Module
# This script validates the organization module configuration

set -e

echo "Testing Organization Module..."

# Change to the organization module directory
cd "$(dirname "$0")/../../modules/avm-foundation/organization"

# Initialize Terraform
echo "Initializing Terraform..."
terraform init -backend=false

# Validate the configuration
echo "Validating Terraform configuration..."
terraform validate

# Format check
echo "Checking Terraform formatting..."
terraform fmt -check

# Create a test plan
echo "Creating test plan..."
terraform plan -var-file="../../../tests/unit/test.tfvars" -out=test.plan

# Validate the plan contains expected resources
echo "Validating plan contents..."
terraform show -json test.plan | jq -r '.planned_values.root_module.resources[].address' | grep -E "(aws_organizations_organizational_unit|aws_organizations_policy)" || {
    echo "ERROR: Expected organizational units and policies not found in plan"
    exit 1
}

# Clean up
rm -f test.plan

echo "Organization Module tests passed!"
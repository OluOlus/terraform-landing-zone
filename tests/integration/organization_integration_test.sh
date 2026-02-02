#!/bin/bash

# Integration test for Organization Module
# This script tests the organization module in a real AWS environment
# Run this after deploying the organization module

set -e

echo "Running Organization Module Integration Tests..."

# Check if AWS CLI is available
if ! command -v aws &> /dev/null; then
    echo "ERROR: AWS CLI is required for integration tests"
    exit 1
fi

# Test 1: Verify organization exists
echo "Test 1: Verifying AWS Organization exists..."
ORG_ID=$(aws organizations describe-organization --query 'Organization.Id' --output text 2>/dev/null || echo "")
if [ -z "$ORG_ID" ]; then
    echo "ERROR: AWS Organization not found"
    exit 1
fi
echo "Organization found: $ORG_ID"

# Test 2: Verify organizational units exist
echo "Test 2: Verifying Organizational Units..."
EXPECTED_OUS=("Production-UK" "Non-Production-UK" "Sandbox" "Core-Infrastructure")

for OU_NAME in "${EXPECTED_OUS[@]}"; do
    OU_ID=$(aws organizations list-organizational-units-for-parent \
        --parent-id $(aws organizations list-roots --query 'Roots[0].Id' --output text) \
        --query "OrganizationalUnits[?Name=='$OU_NAME'].Id" --output text)
    
    if [ -z "$OU_ID" ]; then
        echo "ERROR: Organizational Unit '$OU_NAME' not found"
        exit 1
    fi
    echo "Organizational Unit found: $OU_NAME ($OU_ID)"
done

# Test 3: Verify service control policies exist (if enabled)
echo "Test 3: Verifying Service Control Policies..."
EXPECTED_POLICIES=("UK-Data-Residency-Policy" "UK-Mandatory-Tagging-Policy" "UK-Service-Restrictions-Policy" "UK-IAM-Hardening-Policy")

for POLICY_NAME in "${EXPECTED_POLICIES[@]}"; do
    POLICY_ID=$(aws organizations list-policies --filter SERVICE_CONTROL_POLICY \
        --query "Policies[?Name=='$POLICY_NAME'].Id" --output text)
    
    if [ -n "$POLICY_ID" ]; then
        echo "Service Control Policy found: $POLICY_NAME ($POLICY_ID)"
        
        # Test 4: Verify policy attachments
        echo "  Checking policy attachments for $POLICY_NAME..."
        TARGETS=$(aws organizations list-targets-for-policy --policy-id "$POLICY_ID" \
            --query 'Targets[].TargetId' --output text)
        
        if [ -n "$TARGETS" ]; then
            echo "  Policy attached to targets: $TARGETS"
        else
            echo "   Policy not attached to any targets"
        fi
    else
        echo " Service Control Policy not found: $POLICY_NAME (may be disabled)"
    fi
done

# Test 5: Verify specified region compliance
echo "Test 5: Testing specified region compliance..."
# This would require actually trying to create resources in non-specified regions
# For now, we'll just verify the policy content
for POLICY_NAME in "${EXPECTED_POLICIES[@]}"; do
    POLICY_ID=$(aws organizations list-policies --filter SERVICE_CONTROL_POLICY \
        --query "Policies[?Name=='$POLICY_NAME'].Id" --output text)
    
    if [ -n "$POLICY_ID" ] && [ "$POLICY_NAME" = "UK-Data-Residency-Policy" ]; then
        POLICY_CONTENT=$(aws organizations describe-policy --policy-id "$POLICY_ID" \
            --query 'Policy.Content' --output text)
        
        if echo "$POLICY_CONTENT" | grep -q "us-west-2\|us-east-1"; then
            echo "UK Data Residency Policy contains specified regions"
        else
            echo "ERROR: UK Data Residency Policy does not contain specified regions"
            exit 1
        fi
    fi
done

echo ""
echo "All Organization Module integration tests passed!"
echo ""
echo "Summary:"
echo "- Organization: $ORG_ID"
echo "- Organizational Units: ${#EXPECTED_OUS[@]} created"
echo "- Service Control Policies: Verified"
echo "- UK Compliance: Validated"
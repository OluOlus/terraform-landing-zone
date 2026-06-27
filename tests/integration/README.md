# Integration Tests

This directory contains integration tests for cross-account and connectivity testing.

## Structure

- `cross-account/` - Tests for cross-account role assumptions and permissions
- `networking/` - Tests for network connectivity between accounts
- `logging/` - Tests for log aggregation from all accounts
- `security/` - Tests for security service integration
- `compliance/` - Tests for end-to-end compliance validation

## Running Tests

```bash
# Run all integration tests
make test-integration

# Run the organization integration test directly
bash tests/integration/organization_integration_test.sh

# Run the full repository test suite
make test
```

## Test Requirements

- Multiple AWS accounts configured
- Cross-account roles set up
- Network connectivity established
- Bash

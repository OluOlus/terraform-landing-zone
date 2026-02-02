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
go test ./tests/integration/...

# Run specific integration tests
go test ./tests/integration/cross-account/

# Run with verbose output and timeout
go test -v -timeout 30m ./tests/integration/...
```

## Test Requirements

- Multiple AWS accounts configured
- Cross-account roles set up
- Network connectivity established
- Go 1.19 or higher
- Terratest library
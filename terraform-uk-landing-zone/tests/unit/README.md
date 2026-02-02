# Unit Tests

This directory contains unit tests for individual Terraform modules using Terratest.

## Structure

- `avm-foundation/` - Tests for foundation modules
- `security-services/` - Tests for security service modules  
- `networking/` - Tests for networking modules
- `logging/` - Tests for logging modules
- `storage/` - Tests for storage modules
- `compute/` - Tests for compute modules
- `database/` - Tests for database modules
- `management/` - Tests for management modules

## Running Tests

```bash
# Run all unit tests
go test ./tests/unit/...

# Run specific module tests
go test ./tests/unit/avm-foundation/

# Run with verbose output
go test -v ./tests/unit/...
```

## Test Requirements

- Go 1.19 or higher
- Terratest library
- AWS credentials configured
- Terraform installed
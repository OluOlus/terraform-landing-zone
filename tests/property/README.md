# Property-Based Tests

This directory contains property-based tests that verify universal correctness properties across all inputs.

## Structure

- `foundation/` - Property tests for multi-account foundation integrity
- `compliance/` - Property tests for compliance requirements
- `security/` - Property tests for security controls
- `networking/` - Property tests for network architecture
- `data-residency/` - Property tests for UK data residency enforcement

## Running Tests

```bash
# Run all property tests
go test ./tests/property/...

# Run specific property tests
go test ./tests/property/compliance/

# Run with property test iterations
go test -v -count=100 ./tests/property/...
```

## Property Test Framework

Uses Go's testing framework with custom property test generators:

- Minimum 100 iterations per property test
- Random input generation within valid compliance parameters
- Each test references corresponding design document property
- Tag format: **Feature: uk-aws-secure-landing-zone, Property {number}: {property_text}**
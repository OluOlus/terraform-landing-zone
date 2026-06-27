#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

echo "Running unit tests..."
go test ./tests/unit/...

echo "Running integration tests..."
bash tests/integration/organization_integration_test.sh

echo "Running property-based tests..."
go test -count=100 ./tests/property/...

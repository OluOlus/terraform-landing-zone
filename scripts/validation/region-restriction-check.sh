#!/usr/bin/env bash
# Validates that no Terraform files reference non-UK AWS regions.
# Allowed: eu-west-2 (London), eu-west-1 (Ireland), us-east-1 (global services only).
# Exits 1 if any disallowed region reference is found.

set -euo pipefail

UK_REGIONS=("eu-west-2" "eu-west-1")
# us-east-1 permitted only for global AWS services (IAM, CloudFront, Route53, Billing)
GLOBAL_SERVICES_REGION="us-east-1"
DISALLOWED_REGIONS=(
  "us-east-2" "us-west-1" "us-west-2"
  "ap-southeast-1" "ap-southeast-2" "ap-northeast-1" "ap-northeast-2" "ap-northeast-3"
  "ap-south-1" "ap-east-1"
  "ca-central-1"
  "sa-east-1"
  "af-south-1"
  "me-south-1" "me-central-1"
  "eu-central-1" "eu-central-2" "eu-north-1" "eu-south-1" "eu-south-2"
  "eu-west-3"
)

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

FILES=("$@")
if [[ ${#FILES[@]} -eq 0 ]]; then
  mapfile -t FILES < <(find . -name "*.tf" -not -path "./.terraform/*")
fi

ERRORS=0

for file in "${FILES[@]}"; do
  [[ "$file" == *.tf ]] || continue
  [[ -f "$file" ]] || continue

  # Skip test files and examples
  [[ "$file" == *test* || "$file" == *example* ]] && continue

  for region in "${DISALLOWED_REGIONS[@]}"; do
    # Look for region = "disallowed-region" or "disallowed-region" in region lists
    if grep -qP "\"${region}\"" "$file"; then
      # Check context - exclude comments
      matches=$(grep -nP "\"${region}\"" "$file" | grep -v '^\s*#' || true)
      if [[ -n "$matches" ]]; then
        echo -e "${RED}ERROR${NC}: $file references disallowed region '${region}':"
        echo "$matches" | while read -r line; do
          echo "  $line"
        done
        ERRORS=$((ERRORS + 1))
      fi
    fi
  done

  # Warn about us-east-1 usage outside global service context
  if grep -qP '"us-east-1"' "$file"; then
    # Check if it's in a provider aliased as global/us_east_1
    if grep -P '"us-east-1"' "$file" | grep -qv 'alias\s*=\s*"global\|alias\s*=\s*"us_east_1'; then
      non_global=$(grep -nP '"us-east-1"' "$file" | grep -v 'alias.*global\|alias.*us_east_1\|#' || true)
      if [[ -n "$non_global" ]]; then
        echo -e "${YELLOW}WARNING${NC}: $file uses us-east-1 outside a 'global' provider alias - verify this is for a global AWS service only"
        echo "$non_global" | head -5
      fi
    fi
  fi
done

if [[ $ERRORS -gt 0 ]]; then
  echo -e "${RED}Region restriction check FAILED with $ERRORS error(s)${NC}"
  echo "Only UK regions are permitted: ${UK_REGIONS[*]}"
  echo "us-east-1 is only allowed for global AWS services (IAM, CloudFront, Route53, Billing)"
  exit 1
fi

echo -e "${GREEN}Region restriction check passed - all regions are UK-compliant${NC}"

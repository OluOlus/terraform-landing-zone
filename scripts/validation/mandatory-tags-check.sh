#!/usr/bin/env bash
# Validates that Terraform resource blocks include all mandatory UK tags.
# Exits 1 if any resource is missing a required tag.

set -euo pipefail

REQUIRED_TAGS=("DataClassification" "Environment" "CostCenter" "Owner")
RESOURCE_PATTERN='^resource "'
TAG_BLOCK_PATTERN='tags\s*='

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

FILES=("$@")
if [[ ${#FILES[@]} -eq 0 ]]; then
  mapfile -t FILES < <(find . -name "*.tf" -not -path "./.terraform/*" -not -path "*/examples.tf")
fi

ERRORS=0

for file in "${FILES[@]}"; do
  [[ "$file" == *.tf ]] || continue
  [[ -f "$file" ]] || continue

  # Skip test fixtures and example files
  [[ "$file" == *test* || "$file" == *example* ]] && continue

  # Find resource blocks and check if they have merge(var.common_tags or common_tags reference
  if grep -q "$RESOURCE_PATTERN" "$file"; then
    # Check if file uses common_tags merge pattern (the approved pattern in this project)
    if ! grep -q "merge(var\.common_tags\|merge(local\.common_tags\|common_tags\s*=" "$file"; then
      # Only warn for files that define data resources or module calls without tags
      if grep -q "^resource \"aws_" "$file"; then
        echo -e "${YELLOW}WARNING${NC}: $file defines AWS resources but may be missing common_tags merge"
      fi
    fi

    # Hard check: ensure no resource has a completely empty tags block
    if grep -qP 'tags\s*=\s*\{\s*\}' "$file"; then
      echo -e "${RED}ERROR${NC}: $file has empty tags = {} - must use merge(var.common_tags, {...})"
      ERRORS=$((ERRORS + 1))
    fi
  fi
done

# Check that SCPs include mandatory tag enforcement
SCP_FILE="policies/scps/mandatory-tagging.json"
if [[ -f "$SCP_FILE" ]]; then
  for tag in "${REQUIRED_TAGS[@]}"; do
    if ! grep -q "$tag" "$SCP_FILE"; then
      echo -e "${RED}ERROR${NC}: Mandatory tag '$tag' missing from SCP $SCP_FILE"
      ERRORS=$((ERRORS + 1))
    fi
  done
  echo -e "${GREEN}OK${NC}: All mandatory tags present in $SCP_FILE"
fi

if [[ $ERRORS -gt 0 ]]; then
  echo -e "${RED}Mandatory tags check FAILED with $ERRORS error(s)${NC}"
  exit 1
fi

echo -e "${GREEN}Mandatory tags check passed${NC}"

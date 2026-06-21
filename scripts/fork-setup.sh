#!/usr/bin/env bash
# fork-setup.sh — Interactive configuration script for forks of the AWS Secure Landing Zone.
#
# Run this once after forking to adapt all naming, regions, and placeholders
# to your own organisation.
#
# Usage:
#   chmod +x scripts/fork-setup.sh
#   ./scripts/fork-setup.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${GREEN}[✔]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✘]${NC} $*"; exit 1; }
prompt()  { echo -e "${CYAN}[?]${NC} $*"; }
section() { echo -e "\n${BOLD}── $* ──${NC}\n"; }

# ── Prerequisites ───────────────────────────────────────────────────────────────
check_prereqs() {
  section "Checking prerequisites"
  for cmd in terraform aws git sed find; do
    if command -v "$cmd" &>/dev/null; then
      info "$cmd found: $(command -v "$cmd")"
    else
      error "$cmd is not installed. Please install it and re-run."
    fi
  done
}

# ── Gather configuration ────────────────────────────────────────────────────────
gather_config() {
  section "Organisation configuration"

  echo "This script will replace placeholder values throughout the codebase."
  echo "Press Enter to accept defaults shown in [brackets]."
  echo ""

  prompt "Organisation name (shown in tags and documentation)"
  read -rp "  → [My Organisation]: " ORG_NAME
  ORG_NAME="${ORG_NAME:-My Organisation}"

  prompt "Short org prefix for resource names (lowercase, hyphens OK, e.g. 'myorg')"
  read -rp "  → [myorg]: " ORG_PREFIX
  ORG_PREFIX="${ORG_PREFIX:-myorg}"
  # Validate: lowercase letters and hyphens only
  if ! [[ "$ORG_PREFIX" =~ ^[a-z][a-z0-9-]*$ ]]; then
    error "Prefix must be lowercase letters, numbers, and hyphens, starting with a letter."
  fi

  prompt "Primary AWS region (e.g. eu-west-2, us-east-1, ap-southeast-1)"
  read -rp "  → [eu-west-2]: " PRIMARY_REGION
  PRIMARY_REGION="${PRIMARY_REGION:-eu-west-2}"

  prompt "DR / secondary AWS region"
  read -rp "  → [eu-west-1]: " DR_REGION
  DR_REGION="${DR_REGION:-eu-west-1}"

  prompt "Operations/platform team email"
  read -rp "  → [ops@example.com]: " OPS_EMAIL
  OPS_EMAIL="${OPS_EMAIL:-ops@example.com}"

  prompt "Cloud platform team email"
  read -rp "  → [cloud-platform@example.com]: " PLATFORM_EMAIL
  PLATFORM_EMAIL="${PLATFORM_EMAIL:-cloud-platform@example.com}"

  prompt "GitHub organisation or username (for CODEOWNERS and workflow references)"
  read -rp "  → [OluOlus]: " GITHUB_ORG
  GITHUB_ORG="${GITHUB_ORG:-OluOlus}"

  prompt "Monthly AWS budget limit in USD (for cost alerts)"
  read -rp "  → [5000]: " BUDGET_LIMIT
  BUDGET_LIMIT="${BUDGET_LIMIT:-5000}"

  section "Summary — please confirm"
  echo -e "  Organisation name : ${BOLD}${ORG_NAME}${NC}"
  echo -e "  Resource prefix   : ${BOLD}${ORG_PREFIX}${NC}"
  echo -e "  Primary region    : ${BOLD}${PRIMARY_REGION}${NC}"
  echo -e "  DR region         : ${BOLD}${DR_REGION}${NC}"
  echo -e "  Ops email         : ${BOLD}${OPS_EMAIL}${NC}"
  echo -e "  Platform email    : ${BOLD}${PLATFORM_EMAIL}${NC}"
  echo -e "  GitHub org        : ${BOLD}${GITHUB_ORG}${NC}"
  echo -e "  Monthly budget    : ${BOLD}\$${BUDGET_LIMIT}${NC}"
  echo ""
  read -rp "Proceed with these values? [y/N] " CONFIRM
  [[ "${CONFIRM:-N}" =~ ^[Yy]$ ]] || { warn "Aborted."; exit 0; }
}

# ── In-place replacement helper ─────────────────────────────────────────────────
replace() {
  local search="$1"
  local replacement="$2"
  local file="$3"

  if grep -qF "$search" "$file" 2>/dev/null; then
    if [[ "$OSTYPE" == darwin* ]]; then
      sed -i '' "s|${search}|${replacement}|g" "$file"
    else
      sed -i "s|${search}|${replacement}|g" "$file"
    fi
  fi
}

# ── Apply replacements ──────────────────────────────────────────────────────────
apply_replacements() {
  section "Applying replacements"

  # Gather all files we'll touch (exclude .git, .terraform, binary artefacts)
  mapfile -t ALL_FILES < <(find "$ROOT" -type f \
    \( -name "*.tf" -o -name "*.tfvars" -o -name "*.tfvars.example" \
       -o -name "*.hcl" -o -name "*.yml" -o -name "*.yaml" \
       -o -name "*.md" -o -name "*.sh" -o -name "*.json" \) \
    ! -path '*/.git/*' \
    ! -path '*/.terraform/*' \
    ! -path '*/node_modules/*' \
    ! -path '*/lambda_packages/*')

  total=${#ALL_FILES[@]}
  info "Processing ${total} files…"

  for f in "${ALL_FILES[@]}"; do
    # Resource prefix: uk- → <ORG_PREFIX>-
    replace "uk-landing-zone" "${ORG_PREFIX}-landing-zone" "$f"
    replace "uk-" "${ORG_PREFIX}-" "$f"
    replace "UK " "${ORG_NAME} " "$f"

    # Regions
    replace "eu-west-2" "${PRIMARY_REGION}" "$f"
    replace "eu-west-1" "${DR_REGION}" "$f"

    # Emails
    replace "cloud-platform@example.com" "${PLATFORM_EMAIL}" "$f"
    replace "ops@example.com"            "${OPS_EMAIL}" "$f"
    replace "logging@example.com"        "logging@${OPS_EMAIL#*@}" "$f"

    # GitHub references
    replace "OluOlus"           "${GITHUB_ORG}" "$f"

    # Budget
    replace '"10000"' "\"${BUDGET_LIMIT}\"" "$f"
    replace "'10000'" "'${BUDGET_LIMIT}'"   "$f"
  done

  # Update CODEOWNERS to the new GitHub org
  local codeowners="${ROOT}/.github/CODEOWNERS"
  if [[ -f "$codeowners" ]]; then
    replace "@OluOlus" "@${GITHUB_ORG}" "$codeowners"
    info "Updated CODEOWNERS"
  fi

  info "Replacements complete."
}

# ── Update tfvars examples ───────────────────────────────────────────────────────
update_tfvars_examples() {
  section "Updating backend configs and tfvars examples"

  # Replace management account placeholder in backend configs
  find "$ROOT/backend-configs" -name "*.hcl.example" | while read -r hcl; do
    replace "<MANAGEMENT_ACCOUNT_ID>" "$(prompt_account_id "management")" "$hcl" || true
  done

  info "Done. Rename *.hcl.example files to *.hcl and fill in real account IDs before running terraform init."
}

prompt_account_id() {
  local env="$1"
  read -rp "  AWS Account ID for ${env} (12 digits, or press Enter to skip): " ID
  echo "${ID:-REPLACE_WITH_${env^^}_ACCOUNT_ID}"
}

# ── Post-setup instructions ──────────────────────────────────────────────────────
print_next_steps() {
  section "Next steps"

  echo -e "1. ${BOLD}Review the changes${NC}"
  echo "   git diff --stat"
  echo ""
  echo -e "2. ${BOLD}Fill in real AWS account IDs${NC}"
  echo "   Edit backend-configs/*.hcl.example and rename them to *.hcl"
  echo "   Edit environments/*/terraform.tfvars.example and rename to terraform.tfvars"
  echo ""
  echo -e "3. ${BOLD}Enable MFA on the management account root user${NC} (before bootstrap)"
  echo ""
  echo -e "4. ${BOLD}Run bootstrap${NC} to create Terraform state infrastructure"
  echo "   make bootstrap"
  echo "   # or: chmod +x scripts/deployment/bootstrap.sh && scripts/deployment/bootstrap.sh"
  echo ""
  echo -e "5. ${BOLD}Deploy environments in order${NC}"
  echo "   make init ENVIRONMENT=management  && make plan ENVIRONMENT=management  && make apply ENVIRONMENT=management"
  echo "   make init ENVIRONMENT=security    && make plan ENVIRONMENT=security    && make apply ENVIRONMENT=security"
  echo "   make init ENVIRONMENT=logging     && make plan ENVIRONMENT=logging     && make apply ENVIRONMENT=logging"
  echo "   make init ENVIRONMENT=networking  && make plan ENVIRONMENT=networking  && make apply ENVIRONMENT=networking"
  echo "   make init ENVIRONMENT=sandbox     && make plan ENVIRONMENT=sandbox     && make apply ENVIRONMENT=sandbox"
  echo ""
  echo -e "6. ${BOLD}Configure GitHub Actions secrets${NC} for the PR plan workflow"
  echo "   AWS_PLAN_ROLE_MANAGEMENT, AWS_PLAN_ROLE_SECURITY, AWS_PLAN_ROLE_LOGGING,"
  echo "   AWS_PLAN_ROLE_NETWORKING, AWS_PLAN_ROLE_SANDBOX"
  echo "   (Each should be an IAM role ARN with read-only plan permissions)"
  echo ""
  echo -e "7. ${BOLD}Install pre-commit hooks${NC} in your development environment"
  echo "   pip install pre-commit"
  echo "   pre-commit install && pre-commit install --hook-type commit-msg"
  echo ""
  echo -e "${GREEN}Happy deploying!${NC}"
}

# ── Main ─────────────────────────────────────────────────────────────────────────
main() {
  echo ""
  echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}║   AWS Secure Landing Zone — Fork Setup Script   ║${NC}"
  echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
  echo ""

  check_prereqs
  gather_config
  apply_replacements
  print_next_steps
}

main "$@"

# UK AWS Secure Landing Zone - Makefile
# Provides automation for common tasks

.PHONY: help bootstrap init plan apply destroy test lint security-scan docs clean

# Default target
help: ## Show this help message
	@echo "UK AWS Secure Landing Zone - Available Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Variables
ENVIRONMENT ?= management
AWS_REGION ?= eu-west-2
TERRAFORM_VERSION ?= 1.5.0

# Bootstrap and initialization
bootstrap: ## Bootstrap Terraform state management infrastructure
	@echo "Bootstrapping UK Landing Zone infrastructure..."
	@chmod +x scripts/deployment/bootstrap.sh
	@scripts/deployment/bootstrap.sh

init: ## Initialize Terraform for specified environment
	@echo "Initializing Terraform for $(ENVIRONMENT) environment..."
	@cd environments/$(ENVIRONMENT) && terraform init -backend-config=../../backend-configs/$(ENVIRONMENT).hcl

init-all: ## Initialize Terraform for all environments
	@echo "Initializing all environments..."
	@for env in management security logging networking production-uk non-production-uk sandbox; do \
		echo "Initializing $$env..."; \
		cd environments/$$env && terraform init -backend-config=../../backend-configs/$$env.hcl && cd ../..; \
	done

# Planning and deployment
plan: ## Generate Terraform plan for specified environment
	@echo "Generating plan for $(ENVIRONMENT) environment..."
	@cd environments/$(ENVIRONMENT) && terraform plan -out=tfplan

plan-all: ## Generate Terraform plans for all environments
	@echo "Generating plans for all environments..."
	@for env in management security logging networking production-uk non-production-uk sandbox; do \
		echo "Planning $$env..."; \
		cd environments/$$env && terraform plan -out=tfplan && cd ../..; \
	done

apply: ## Apply Terraform plan for specified environment
	@echo "Applying plan for $(ENVIRONMENT) environment..."
	@cd environments/$(ENVIRONMENT) && terraform apply tfplan

apply-all: ## Apply Terraform plans for all environments (DANGEROUS)
	@echo "WARNING: This will apply changes to ALL environments!"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		for env in management security logging networking production-uk non-production-uk sandbox; do \
			echo "Applying $$env..."; \
			cd environments/$$env && terraform apply -auto-approve && cd ../..; \
		done; \
	fi

destroy: ## Destroy Terraform resources for specified environment
	@echo "WARNING: This will destroy resources in $(ENVIRONMENT) environment!"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		cd environments/$(ENVIRONMENT) && terraform destroy; \
	fi

# Testing
test: ## Run all tests
	@echo "Running all tests..."
	@scripts/validation/run-all-tests.sh

test-unit: ## Run unit tests
	@echo "Running unit tests..."
	@cd tests && go test ./unit/...

test-integration: ## Run integration tests
	@echo "Running integration tests..."
	@cd tests && go test -timeout 30m ./integration/...

test-property: ## Run property-based tests
	@echo "Running property-based tests..."
	@cd tests && go test -count=100 ./property/...

# Code quality and security
lint: ## Run linting checks
	@echo "Running linting checks..."
	@terraform fmt -recursive .
	@tflint --config .tflint.hcl --recursive .

security-scan: ## Run security scans
	@echo "Running security scans..."
	@tfsec --config-file .tfsec.yml .
	@checkov --config-file .checkov.yml --directory .

compliance-check: ## Run UK compliance checks
	@echo "Running UK compliance checks..."
	@chmod +x scripts/validation/uk-compliance-check.sh
	@scripts/validation/uk-compliance-check.sh

pre-commit: ## Run pre-commit hooks
	@echo "Running pre-commit hooks..."
	@pre-commit run --all-files

# Documentation
docs: ## Generate documentation
	@echo "Generating documentation..."
	@terraform-docs markdown table --output-file README.md --output-mode inject .
	@for dir in modules/*/; do \
		terraform-docs markdown table --output-file README.md --output-mode inject $$dir; \
	done

docs-serve: ## Serve documentation locally
	@echo "Serving documentation..."
	@cd docs && python3 -m http.server 8000

# Utilities
validate: ## Validate Terraform configuration
	@echo "Validating Terraform configuration..."
	@terraform fmt -check -recursive .
	@for env in management security logging networking production-uk non-production-uk sandbox; do \
		echo "Validating $$env..."; \
		cd environments/$$env && terraform validate && cd ../..; \
	done

format: ## Format Terraform files
	@echo "Formatting Terraform files..."
	@terraform fmt -recursive .

clean: ## Clean temporary files
	@echo "Cleaning temporary files..."
	@find . -name "*.tfplan" -delete
	@find . -name ".terraform" -type d -exec rm -rf {} + 2>/dev/null || true
	@find . -name "crash.log" -delete
	@rm -rf backend-configs/

version: ## Show version information
	@echo "UK AWS Secure Landing Zone Version Information:"
	@echo "Terraform: $$(terraform version | head -n1)"
	@echo "AWS CLI: $$(aws --version)"
	@echo "Go: $$(go version)"
	@echo "TFLint: $$(tflint --version)"
	@echo "TFSec: $$(tfsec --version)"
	@echo "Checkov: $$(checkov --version)"

# Environment-specific shortcuts
management: ## Quick deployment for management environment
	$(MAKE) ENVIRONMENT=management init plan apply

security: ## Quick deployment for security environment
	$(MAKE) ENVIRONMENT=security init plan apply

logging: ## Quick deployment for logging environment
	$(MAKE) ENVIRONMENT=logging init plan apply

networking: ## Quick deployment for networking environment
	$(MAKE) ENVIRONMENT=networking init plan apply

production-uk: ## Quick deployment for production-uk environment
	$(MAKE) ENVIRONMENT=production-uk init plan apply

# CI/CD targets
ci-validate: ## CI validation pipeline
	@echo "Running CI validation..."
	@terraform fmt -check -recursive .
	@$(MAKE) validate
	@$(MAKE) lint
	@$(MAKE) security-scan
	@$(MAKE) compliance-check

ci-test: ## CI test pipeline
	@echo "Running CI tests..."
	@$(MAKE) test-unit
	@$(MAKE) test-integration

ci-deploy: ## CI deployment pipeline
	@echo "Running CI deployment..."
	@$(MAKE) plan-all
	@$(MAKE) apply-all
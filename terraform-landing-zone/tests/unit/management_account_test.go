package test

import (
	"testing"

	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
)

func TestManagementAccountModule(t *testing.T) {
	t.Parallel()

	// Define the Terraform options
	terraformOptions := &terraform.Options{
		// Path to the Terraform code that will be tested
		TerraformDir: "../../modules/avm-foundation/management-account",

		// Variables to pass to the Terraform code
		Vars: map[string]interface{}{
			"management_account_name":  "UK-Landing-Zone-Test",
			"management_account_email": "test@example.com",
			"common_tags": map[string]string{
				"Project":             "UK-Landing-Zone-Test",
				"ManagedBy":           "Terraform",
				"DataClassification":  "Internal",
				"Environment":         "Test",
				"CostCenter":          "Platform",
				"Owner":               "Platform-Team",
				"ComplianceFramework": "NCSC-UK-GDPR",
				"DataResidency":       "UK",
			},
			"force_destroy_buckets": true,
		},

		// Disable colors in Terraform commands so it's easier to parse stdout/stderr
		NoColor: true,
	}

	// Clean up resources with "terraform destroy" at the end of the test
	defer terraform.Destroy(t, terraformOptions)

	// Run "terraform init" and "terraform plan" to validate the configuration
	terraform.InitAndPlan(t, terraformOptions)

	// Validate that the plan contains expected resources
	planOutput := terraform.Plan(t, terraformOptions)

	// Check that the plan includes the expected resources
	assert.Contains(t, planOutput, "aws_organizations_organization.main")
	assert.Contains(t, planOutput, "aws_organizations_organizational_unit.production_uk")
	assert.Contains(t, planOutput, "aws_organizations_organizational_unit.non_production_uk")
	assert.Contains(t, planOutput, "aws_organizations_organizational_unit.sandbox")
	assert.Contains(t, planOutput, "aws_organizations_policy.uk_data_residency")
	assert.Contains(t, planOutput, "aws_organizations_policy.mandatory_tagging")
	assert.Contains(t, planOutput, "aws_organizations_policy.service_restrictions")
	assert.Contains(t, planOutput, "aws_organizations_policy.iam_hardening")
	assert.Contains(t, planOutput, "aws_config_configuration_recorder.management")
	assert.Contains(t, planOutput, "aws_s3_bucket.config")
	assert.Contains(t, planOutput, "aws_kms_key.config")
}

func TestManagementAccountModuleValidation(t *testing.T) {
	t.Parallel()

	// Test with invalid email
	terraformOptions := &terraform.Options{
		TerraformDir: "../../modules/avm-foundation/management-account",
		Vars: map[string]interface{}{
			"management_account_email": "invalid-email",
		},
		NoColor: true,
	}

	// This should fail validation
	_, err := terraform.InitAndPlanE(t, terraformOptions)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Management account email must be a valid email address")
}

func TestManagementAccountModuleRegionValidation(t *testing.T) {
	t.Parallel()

	// Test with invalid AWS region
	terraformOptions := &terraform.Options{
		TerraformDir: "../../modules/avm-foundation/management-account",
		Vars: map[string]interface{}{
			"management_account_email": "test@example.com",
			"aws_regions":              []string{"us-east-1", "us-west-2"},
		},
		NoColor: true,
	}

	// This should fail validation
	_, err := terraform.InitAndPlanE(t, terraformOptions)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Only UK regions (eu-west-1, eu-west-2) are allowed")
}

func TestManagementAccountModuleConfigDeliveryFrequency(t *testing.T) {
	t.Parallel()

	// Test with invalid config delivery frequency
	terraformOptions := &terraform.Options{
		TerraformDir: "../../modules/avm-foundation/management-account",
		Vars: map[string]interface{}{
			"management_account_email":   "test@example.com",
			"config_delivery_frequency": "Invalid_Frequency",
		},
		NoColor: true,
	}

	// This should fail validation
	_, err := terraform.InitAndPlanE(t, terraformOptions)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Config delivery frequency must be a valid AWS Config delivery frequency")
}
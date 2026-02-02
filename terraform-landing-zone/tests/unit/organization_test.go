package test

import (
	"testing"

	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
)

func TestOrganizationModule(t *testing.T) {
	t.Parallel()

	// Define the Terraform options
	terraformOptions := &terraform.Options{
		// Path to the Terraform code that will be tested
		TerraformDir: "../../modules/avm-foundation/organization",

		// Variables to pass to the Terraform code
		Vars: map[string]interface{}{
			"common_tags": map[string]string{
				"Project":             "UK-AWS-Secure-Landing-Zone",
				"ManagedBy":          "Terraform",
				"ComplianceFramework": "NCSC-Cloud-Security-Principles",
				"DataResidency":      "UK",
				"Environment":        "test",
			},
			"enable_service_control_policies": false, // Disable SCPs for unit test
			"policy_path":                    "../../policies/scps",
		},

		// Disable colors in Terraform commands so it's easier to parse stdout/stderr
		NoColor: true,
	}

	// Clean up resources with "terraform destroy" at the end of the test
	defer terraform.Destroy(t, terraformOptions)

	// Run "terraform init" and "terraform plan"
	terraform.InitAndPlan(t, terraformOptions)

	// Validate that the plan contains the expected resources
	planOutput := terraform.Plan(t, terraformOptions)

	// Check that the plan includes organizational units
	assert.Contains(t, planOutput, "aws_organizations_organizational_unit.production_uk")
	assert.Contains(t, planOutput, "aws_organizations_organizational_unit.non_production_uk")
	assert.Contains(t, planOutput, "aws_organizations_organizational_unit.sandbox")
	assert.Contains(t, planOutput, "aws_organizations_organizational_unit.core_infrastructure")
}

func TestOrganizationModuleWithSCPs(t *testing.T) {
	t.Parallel()

	// Define the Terraform options with SCPs enabled
	terraformOptions := &terraform.Options{
		// Path to the Terraform code that will be tested
		TerraformDir: "../../modules/avm-foundation/organization",

		// Variables to pass to the Terraform code
		Vars: map[string]interface{}{
			"common_tags": map[string]string{
				"Project":             "UK-AWS-Secure-Landing-Zone",
				"ManagedBy":          "Terraform",
				"ComplianceFramework": "NCSC-Cloud-Security-Principles",
				"DataResidency":      "UK",
				"Environment":        "test",
			},
			"enable_service_control_policies": true,
			"policy_path":                    "../../policies/scps",
		},

		// Disable colors in Terraform commands so it's easier to parse stdout/stderr
		NoColor: true,
	}

	// Clean up resources with "terraform destroy" at the end of the test
	defer terraform.Destroy(t, terraformOptions)

	// Run "terraform init" and "terraform plan"
	terraform.InitAndPlan(t, terraformOptions)

	// Validate that the plan contains the expected resources
	planOutput := terraform.Plan(t, terraformOptions)

	// Check that the plan includes service control policies
	assert.Contains(t, planOutput, "aws_organizations_policy.uk_data_residency")
	assert.Contains(t, planOutput, "aws_organizations_policy.mandatory_tagging")
	assert.Contains(t, planOutput, "aws_organizations_policy.service_restrictions")
	assert.Contains(t, planOutput, "aws_organizations_policy.iam_hardening")

	// Check that the plan includes policy attachments
	assert.Contains(t, planOutput, "aws_organizations_policy_attachment.uk_data_residency_production")
	assert.Contains(t, planOutput, "aws_organizations_policy_attachment.mandatory_tagging_production")
	assert.Contains(t, planOutput, "aws_organizations_policy_attachment.service_restrictions_production")
	assert.Contains(t, planOutput, "aws_organizations_policy_attachment.iam_hardening_production")
}

func TestOrganizationModuleOutputs(t *testing.T) {
	t.Parallel()

	// Define the Terraform options
	terraformOptions := &terraform.Options{
		// Path to the Terraform code that will be tested
		TerraformDir: "../../modules/avm-foundation/organization",

		// Variables to pass to the Terraform code
		Vars: map[string]interface{}{
			"common_tags": map[string]string{
				"Project":             "UK-AWS-Secure-Landing-Zone",
				"ManagedBy":          "Terraform",
				"ComplianceFramework": "NCSC-Cloud-Security-Principles",
				"DataResidency":      "UK",
				"Environment":        "test",
			},
			"enable_service_control_policies": false, // Disable SCPs for unit test
			"policy_path":                    "../../policies/scps",
		},

		// Disable colors in Terraform commands so it's easier to parse stdout/stderr
		NoColor: true,
	}

	// Clean up resources with "terraform destroy" at the end of the test
	defer terraform.Destroy(t, terraformOptions)

	// Run "terraform init" and "terraform plan"
	terraform.InitAndPlan(t, terraformOptions)

	// Validate that the plan contains expected outputs
	planOutput := terraform.Plan(t, terraformOptions)

	// Check for output declarations (these would be in the plan as output values)
	assert.Contains(t, planOutput, "organization_id")
	assert.Contains(t, planOutput, "production_uk_ou_id")
	assert.Contains(t, planOutput, "non_production_uk_ou_id")
	assert.Contains(t, planOutput, "sandbox_ou_id")
	assert.Contains(t, planOutput, "core_infrastructure_ou_id")
}
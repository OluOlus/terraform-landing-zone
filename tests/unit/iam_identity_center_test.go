package test

import (
	"testing"

	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
)

func TestIAMIdentityCenterModule(t *testing.T) {
	t.Parallel()

	// Define the Terraform options
	terraformOptions := &terraform.Options{
		// Path to the Terraform code that will be tested
		TerraformDir: "../../modules/avm-foundation/iam-identity-center",

		// Variables to pass to the Terraform code
		Vars: map[string]interface{}{
			"common_tags": map[string]string{
				"Environment":        "test",
				"DataClassification": "internal",
				"CostCenter":        "security",
				"Owner":             "test-team",
				"Project":           "uk-landing-zone-test",
			},
			"enable_break_glass_monitoring": true,
			"break_glass_alarm_actions":     []string{},
		},

		// Disable colors in Terraform commands so it's easier to parse stdout/stderr
		NoColor: true,
	}

	// Clean up resources with "terraform destroy" at the end of the test
	defer terraform.Destroy(t, terraformOptions)

	// Run "terraform init" and "terraform plan"
	terraform.InitAndPlan(t, terraformOptions)

	// Validate the plan
	planOutput := terraform.Plan(t, terraformOptions)

	// Check that the plan includes the expected resources
	assert.Contains(t, planOutput, "aws_ssoadmin_permission_set.security_admin")
	assert.Contains(t, planOutput, "aws_ssoadmin_permission_set.network_admin")
	assert.Contains(t, planOutput, "aws_ssoadmin_permission_set.developer")
	assert.Contains(t, planOutput, "aws_ssoadmin_permission_set.viewer")
	assert.Contains(t, planOutput, "aws_ssoadmin_permission_set.break_glass")

	// Check that MFA policies are included
	assert.Contains(t, planOutput, "aws_ssoadmin_permission_set_inline_policy.security_admin_mfa")
	assert.Contains(t, planOutput, "aws_ssoadmin_permission_set_inline_policy.network_admin_mfa")
	assert.Contains(t, planOutput, "aws_ssoadmin_permission_set_inline_policy.developer_mfa")
	assert.Contains(t, planOutput, "aws_ssoadmin_permission_set_inline_policy.viewer_mfa")
	assert.Contains(t, planOutput, "aws_ssoadmin_permission_set_inline_policy.break_glass_mfa")

	// Check that break glass monitoring is included
	assert.Contains(t, planOutput, "aws_cloudwatch_log_metric_filter.break_glass_usage")
	assert.Contains(t, planOutput, "aws_cloudwatch_metric_alarm.break_glass_usage")
}

func TestIAMIdentityCenterModuleWithoutBreakGlassMonitoring(t *testing.T) {
	t.Parallel()

	// Define the Terraform options
	terraformOptions := &terraform.Options{
		// Path to the Terraform code that will be tested
		TerraformDir: "../../modules/avm-foundation/iam-identity-center",

		// Variables to pass to the Terraform code
		Vars: map[string]interface{}{
			"common_tags": map[string]string{
				"Environment":        "test",
				"DataClassification": "internal",
				"CostCenter":        "security",
				"Owner":             "test-team",
				"Project":           "uk-landing-zone-test",
			},
			"enable_break_glass_monitoring": false,
		},

		// Disable colors in Terraform commands so it's easier to parse stdout/stderr
		NoColor: true,
	}

	// Clean up resources with "terraform destroy" at the end of the test
	defer terraform.Destroy(t, terraformOptions)

	// Run "terraform init" and "terraform plan"
	terraform.InitAndPlan(t, terraformOptions)

	// Validate the plan
	planOutput := terraform.Plan(t, terraformOptions)

	// Check that break glass monitoring is NOT included when disabled
	assert.NotContains(t, planOutput, "aws_cloudwatch_log_metric_filter.break_glass_usage")
	assert.NotContains(t, planOutput, "aws_cloudwatch_metric_alarm.break_glass_usage")

	// But permission sets should still be there
	assert.Contains(t, planOutput, "aws_ssoadmin_permission_set.break_glass")
}

func TestIAMIdentityCenterModuleValidation(t *testing.T) {
	t.Parallel()

	// Define the Terraform options
	terraformOptions := &terraform.Options{
		// Path to the Terraform code that will be tested
		TerraformDir: "../../modules/avm-foundation/iam-identity-center",

		// Variables to pass to the Terraform code
		Vars: map[string]interface{}{
			"common_tags": map[string]string{
				"Environment":        "test",
				"DataClassification": "internal",
				"CostCenter":        "security",
				"Owner":             "test-team",
				"Project":           "uk-landing-zone-test",
			},
		},

		// Disable colors in Terraform commands so it's easier to parse stdout/stderr
		NoColor: true,
	}

	// Run "terraform init" and "terraform validate"
	terraform.Init(t, terraformOptions)
	terraform.Validate(t, terraformOptions)
}
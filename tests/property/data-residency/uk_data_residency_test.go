package property_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var allowedRegions = []string{"eu-west-2", "eu-west-1"}

// TestUKDataResidencySCPContainsRegionDeny validates that the UK data residency SCP
// explicitly denies non-UK regions.
func TestUKDataResidencySCPContainsRegionDeny(t *testing.T) {
	t.Parallel()

	scpPath := filepath.Join("..", "..", "..", "policies", "scps", "uk-data-residency.json")
	content, err := os.ReadFile(scpPath)
	require.NoError(t, err, "uk-data-residency.json must exist")

	var policy map[string]interface{}
	require.NoError(t, json.Unmarshal(content, &policy), "SCP must be valid JSON")

	statements, ok := policy["Statement"].([]interface{})
	require.True(t, ok, "SCP must have Statement array")

	foundDenyNonUK := false
	for _, stmt := range statements {
		s := stmt.(map[string]interface{})
		if s["Sid"] == "DenyNonUKRegions" {
			foundDenyNonUK = true
			assert.Equal(t, "Deny", s["Effect"], "DenyNonUKRegions must have Deny effect")
		}
	}
	assert.True(t, foundDenyNonUK, "SCP must contain DenyNonUKRegions statement")
}

// TestUKDataResidencySCPContainsUKRegions validates that the SCP allows UK regions.
func TestUKDataResidencySCPContainsUKRegions(t *testing.T) {
	t.Parallel()

	scpPath := filepath.Join("..", "..", "..", "policies", "scps", "uk-data-residency.json")
	content, err := os.ReadFile(scpPath)
	require.NoError(t, err)

	scpStr := string(content)
	for _, region := range allowedRegions {
		assert.Contains(t, scpStr, region,
			"UK data residency SCP must reference UK region %s", region)
	}
}

// TestNoDisallowedRegionsInTerraformModules validates that no Terraform module files
// reference disallowed (non-UK) regions as defaults.
func TestNoDisallowedRegionsInTerraformModules(t *testing.T) {
	t.Parallel()

	modulesDir := filepath.Join("..", "..", "..", "modules")

	err := filepath.Walk(modulesDir, func(path string, info os.FileInfo, err error) error {
		require.NoError(t, err)
		if info.IsDir() || !strings.HasSuffix(path, ".tf") {
			return nil
		}

		content, readErr := os.ReadFile(path)
		require.NoError(t, readErr, "should be able to read %s", path)
		fileStr := string(content)

		for _, region := range disallowedRegions {
			if strings.Contains(fileStr, `"`+region+`"`) {
				t.Errorf("Module file %s references disallowed region %q", path, region)
			}
		}
		return nil
	})
	require.NoError(t, err)
}

// TestIAMPoliciesEnforceUKRegions validates that IAM policies restrict to UK regions.
func TestIAMPoliciesEnforceUKRegions(t *testing.T) {
	t.Parallel()

	iamPoliciesDir := filepath.Join("..", "..", "..", "policies", "iam-policies")
	entries, err := os.ReadDir(iamPoliciesDir)
	require.NoError(t, err)

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		path := filepath.Join(iamPoliciesDir, entry.Name())
		content, err := os.ReadFile(path)
		require.NoError(t, err)

		// Check that at least one of the UK regions is referenced in the policy
		policyStr := string(content)
		hasUKRegion := false
		for _, region := range allowedRegions {
			if strings.Contains(policyStr, region) {
				hasUKRegion = true
				break
			}
		}

		// Viewer policy may not have region restrictions - that's acceptable
		if entry.Name() != "viewer.json" {
			assert.True(t, hasUKRegion,
				"IAM policy %s should reference UK regions for data residency enforcement", entry.Name())
		}

		// Check no disallowed regions appear
		for _, region := range disallowedRegions {
			assert.NotContains(t, policyStr, `"`+region+`"`,
				"IAM policy %s must not reference disallowed region %s", entry.Name(), region)
		}
	}
}

// TestEnvironmentProvidersUseUKRegions validates that environment Terraform configs
// configure providers with UK regions.
func TestEnvironmentProvidersUseUKRegions(t *testing.T) {
	t.Parallel()

	environmentsDir := filepath.Join("..", "..", "..", "environments")
	entries, err := os.ReadDir(environmentsDir)
	require.NoError(t, err)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		mainTF := filepath.Join(environmentsDir, entry.Name(), "main.tf")
		if _, err := os.Stat(mainTF); os.IsNotExist(err) {
			continue
		}

		content, err := os.ReadFile(mainTF)
		require.NoError(t, err)
		fileStr := string(content)

		// Every environment must reference eu-west-2 as primary
		assert.Contains(t, fileStr, "eu-west-2",
			"Environment %s must use eu-west-2 as primary region", entry.Name())
	}
}

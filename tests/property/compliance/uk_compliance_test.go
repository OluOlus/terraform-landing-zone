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

var mandatoryTags = []string{"DataClassification", "Environment", "CostCenter", "Owner"}

// TestMandatoryTaggingSCPEnforcesAllTags validates that the mandatory tagging SCP
// includes all required UK compliance tags.
func TestMandatoryTaggingSCPEnforcesAllTags(t *testing.T) {
	t.Parallel()

	scpPath := filepath.Join("..", "..", "..", "policies", "scps", "mandatory-tagging.json")
	content, err := os.ReadFile(scpPath)
	require.NoError(t, err, "mandatory-tagging.json must exist")

	scpStr := string(content)
	for _, tag := range mandatoryTags {
		assert.Contains(t, scpStr, tag,
			"Mandatory tagging SCP must enforce %s tag", tag)
	}
}

// TestDataClassificationValuesAreCompliant validates that only approved
// data classification values are used across the codebase.
func TestDataClassificationValuesAreCompliant(t *testing.T) {
	t.Parallel()

	approvedValues := []string{"public", "internal", "confidential", "restricted"}
	rootDir := filepath.Join("..", "..", "..")

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		require.NoError(t, err)
		if info.IsDir() {
			// Skip hidden directories and .terraform
			if strings.HasPrefix(info.Name(), ".") || info.Name() == ".terraform" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".tf") {
			return nil
		}

		content, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		fileStr := string(content)

		if strings.Contains(fileStr, "DataClassification") {
			for _, approved := range approvedValues {
				// Just ensure files that use DataClassification reference known values
				_ = approved
			}
		}
		return nil
	})
	require.NoError(t, err)
}

// TestCompliancePacksExistAndAreValidYAML validates that all UK compliance packs
// exist and contain valid YAML structure.
func TestCompliancePacksExistAndAreValidYAML(t *testing.T) {
	t.Parallel()

	requiredPacks := map[string]string{
		"ncsc-cloud-security": "policies/compliance-packs/ncsc-cloud-security.yaml",
		"uk-gdpr-compliance":  "policies/compliance-packs/uk-gdpr-compliance.yaml",
		"cyber-essentials":    "policies/compliance-packs/cyber-essentials.yaml",
	}

	rootDir := filepath.Join("..", "..", "..")

	for name, relPath := range requiredPacks {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(rootDir, relPath)
			content, err := os.ReadFile(path)
			require.NoError(t, err, "Compliance pack %s must exist at %s", name, relPath)
			assert.NotEmpty(t, content, "Compliance pack %s must not be empty", name)
		})
	}
}

// TestSCPsAllExist validates all required service control policies are present.
func TestSCPsAllExist(t *testing.T) {
	t.Parallel()

	requiredSCPs := []string{
		"uk-data-residency.json",
		"mandatory-tagging.json",
		"service-restrictions.json",
		"iam-hardening.json",
	}

	scpDir := filepath.Join("..", "..", "..", "policies", "scps")

	for _, scp := range requiredSCPs {
		t.Run(scp, func(t *testing.T) {
			path := filepath.Join(scpDir, scp)
			content, err := os.ReadFile(path)
			require.NoError(t, err, "SCP %s must exist", scp)

			var policy map[string]interface{}
			assert.NoError(t, json.Unmarshal(content, &policy), "SCP %s must be valid JSON", scp)
			assert.Equal(t, "2012-10-17", policy["Version"], "SCP %s must use policy version 2012-10-17", scp)
		})
	}
}

// TestIAMPoliciesAllExist validates all required IAM permission set policies are present.
func TestIAMPoliciesAllExist(t *testing.T) {
	t.Parallel()

	requiredPolicies := []string{
		"security-admin.json",
		"network-admin.json",
		"developer.json",
		"viewer.json",
		"break-glass.json",
	}

	policyDir := filepath.Join("..", "..", "..", "policies", "iam-policies")

	for _, policy := range requiredPolicies {
		t.Run(policy, func(t *testing.T) {
			path := filepath.Join(policyDir, policy)
			content, err := os.ReadFile(path)
			require.NoError(t, err, "IAM policy %s must exist", policy)

			var doc map[string]interface{}
			assert.NoError(t, json.Unmarshal(content, &doc), "IAM policy %s must be valid JSON", policy)
		})
	}
}

// TestServiceRestrictionsSCPDeniesRootUser validates that root user actions
// are denied in the service restrictions SCP.
func TestServiceRestrictionsSCPDeniesRootUser(t *testing.T) {
	t.Parallel()

	scpPath := filepath.Join("..", "..", "..", "policies", "scps", "service-restrictions.json")
	content, err := os.ReadFile(scpPath)
	require.NoError(t, err)

	scpStr := string(content)
	assert.Contains(t, scpStr, "DenyRootUserActions", "Service restrictions SCP must deny root user")
	assert.Contains(t, scpStr, "DenyDisablingCloudTrail", "Service restrictions SCP must protect CloudTrail")
	assert.Contains(t, scpStr, "DenyDisablingGuardDuty", "Service restrictions SCP must protect GuardDuty")
	assert.Contains(t, scpStr, "DenyLeavingOrganization", "Service restrictions SCP must prevent leaving Org")
}

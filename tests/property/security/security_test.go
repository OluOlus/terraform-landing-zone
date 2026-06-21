package property_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rootDir resolves the Terraform project root relative to the package directory
// that `go test` uses as its working directory.
func rootDir(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("cannot resolve root dir: %v", err)
	}
	return abs
}

// assertFileExists fails the test if path does not exist or cannot be stat'd.
func assertFileExists(t *testing.T, path, description string) bool {
	t.Helper()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("missing required file (%s): %s", description, path)
		return false
	}
	return true
}

// assertDirExists fails the test if path is not an existing directory.
func assertDirExists(t *testing.T, path, description string) bool {
	t.Helper()
	info, err := os.Stat(path)
	if os.IsNotExist(err) || (err == nil && !info.IsDir()) {
		t.Errorf("missing required directory (%s): %s", description, path)
		return false
	}
	return true
}

// TestProperty4_NCSCCloudSecurityPrinciples verifies that the structural
// foundations for NCSC Cloud Security Principles compliance are in place:
//
//  1. A KMS module exists with an aws_kms_key resource (encryption at rest).
//  2. All expected security-services sub-modules are present.
//  3. The policies/scps/ directory contains JSON SCP files.
func TestProperty4_NCSCCloudSecurityPrinciples(t *testing.T) {
	t.Parallel()

	root := rootDir(t)

	// --- 1. KMS module must exist and declare an aws_kms_key resource ---
	kmsMain := filepath.Join(root, "modules", "security", "kms", "main.tf")
	if assertFileExists(t, kmsMain, "KMS module main.tf") {
		raw, err := os.ReadFile(kmsMain)
		if err != nil {
			t.Errorf("cannot read %s: %v", kmsMain, err)
		} else if !strings.Contains(string(raw), "aws_kms_key") {
			t.Errorf(
				"%s: KMS module must declare an 'aws_kms_key' resource to satisfy "+
					"NCSC Cloud Security Principle 2 (asset protection / encryption)",
				kmsMain,
			)
		}
	}

	// --- 2. Security-services sub-modules must all be present ---
	expectedSecurityServices := []string{
		"config",
		"guardduty",
		"security-automation",
		"security-hub",
	}
	secServicesDir := filepath.Join(root, "modules", "security-services")
	assertDirExists(t, secServicesDir, "security-services module directory")

	for _, svc := range expectedSecurityServices {
		svcDir := filepath.Join(secServicesDir, svc)
		assertDirExists(t, svcDir,
			"security-services/"+svc+" sub-module")
	}

	// --- 3. SCP files must exist in policies/scps/ ---
	scpDir := filepath.Join(root, "policies", "scps")
	assertDirExists(t, scpDir, "policies/scps directory")

	entries, err := os.ReadDir(scpDir)
	if err != nil {
		t.Fatalf("cannot read SCP directory %s: %v", scpDir, err)
	}

	jsonCount := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			jsonCount++
		}
	}
	if jsonCount == 0 {
		t.Errorf(
			"policies/scps/ contains no JSON files — at least one SCP JSON policy is required "+
				"to satisfy NCSC Cloud Security Principles",
		)
	}
}

// TestProperty6_ComprehensiveSecurityControls validates that:
//
//  1. Each SCP JSON file is valid JSON and contains the mandatory "Version" and
//     "Statement" keys.
//  2. AWS Config and GuardDuty modules each contain a main.tf, confirming
//     detective security controls are implemented.
func TestProperty6_ComprehensiveSecurityControls(t *testing.T) {
	t.Parallel()

	root := rootDir(t)

	// --- 1. Validate all SCP JSON files ---
	scpDir := filepath.Join(root, "policies", "scps")
	entries, err := os.ReadDir(scpDir)
	if err != nil {
		t.Fatalf("cannot read SCP directory %s: %v", scpDir, err)
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		entry := entry // capture for sub-test
		t.Run("scp/"+entry.Name(), func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(scpDir, entry.Name())
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("cannot read %s: %v", path, err)
			}

			var policy map[string]interface{}
			if err := json.Unmarshal(raw, &policy); err != nil {
				t.Fatalf("%s: invalid JSON — %v", path, err)
			}

			if _, ok := policy["Version"]; !ok {
				t.Errorf("%s: SCP policy is missing required 'Version' key", path)
			}
			if _, ok := policy["Statement"]; !ok {
				t.Errorf("%s: SCP policy is missing required 'Statement' key", path)
			}

			// Statement must be a non-empty array
			stmts, ok := policy["Statement"].([]interface{})
			if !ok || len(stmts) == 0 {
				t.Errorf(
					"%s: 'Statement' must be a non-empty array — empty SCP provides no protection",
					path,
				)
			}
		})
	}

	// --- 2. Detective controls: Config and GuardDuty must each have main.tf ---
	detectiveControls := map[string]string{
		"AWS Config":   filepath.Join(root, "modules", "security-services", "config", "main.tf"),
		"AWS GuardDuty": filepath.Join(root, "modules", "security-services", "guardduty", "main.tf"),
	}

	for service, mainTF := range detectiveControls {
		service, mainTF := service, mainTF
		t.Run("detective-control/"+service, func(t *testing.T) {
			t.Parallel()
			assertFileExists(t, mainTF,
				service+" main.tf (required for comprehensive security controls)")
		})
	}
}

package property_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rootDir resolves the Terraform project root relative to the working directory
// that `go test` sets for this package (tests/property/compliance/).
func rootDir(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("cannot resolve root dir: %v", err)
	}
	return abs
}

// assertFileExists fails the test if the given path does not exist and returns
// false so the caller can skip dependent checks.
func assertFileExists(t *testing.T, path, description string) bool {
	t.Helper()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("missing required file (%s): %s", description, path)
		return false
	}
	return true
}

// assertDirExists fails the test if the given path is not an existing directory.
func assertDirExists(t *testing.T, path, description string) bool {
	t.Helper()
	info, err := os.Stat(path)
	if os.IsNotExist(err) || (err == nil && !info.IsDir()) {
		t.Errorf("missing required directory (%s): %s", description, path)
		return false
	}
	return true
}

// TestProperty5_UKGDPRCompliance verifies that the structural artefacts
// required for UK GDPR compliance are all present:
//
//  1. The UK GDPR compliance pack YAML file exists.
//  2. CloudTrail module is present (audit trail for data access events).
//  3. Log-retention module is present (enforces GDPR data-retention periods).
//  4. Security-automation module is present (auto-remediation of compliance drift).
func TestProperty5_UKGDPRCompliance(t *testing.T) {
	t.Parallel()

	root := rootDir(t)

	// --- 1. UK GDPR compliance pack ---
	gdprPack := filepath.Join(root, "policies", "compliance-packs", "uk-gdpr-compliance.yaml")
	assertFileExists(t, gdprPack,
		"UK GDPR compliance pack YAML — required to document GDPR control mappings")

	// --- 2. CloudTrail — audit trail of all API calls ---
	cloudtrailMain := filepath.Join(root, "modules", "logging", "cloudtrail", "main.tf")
	assertFileExists(t, cloudtrailMain,
		"CloudTrail module main.tf — required for UK GDPR audit trail (Article 30 records)")

	// --- 3. Log-retention — GDPR-compliant data-retention enforcement ---
	logRetentionMain := filepath.Join(root, "modules", "logging", "log-retention", "main.tf")
	assertFileExists(t, logRetentionMain,
		"Log-retention module main.tf — required to enforce GDPR-compliant log retention periods")

	// --- 4. Security automation — auto-remediation of compliance violations ---
	secAutoMain := filepath.Join(root, "modules", "security-services", "security-automation", "main.tf")
	assertFileExists(t, secAutoMain,
		"Security-automation module main.tf — required for automated GDPR compliance remediation")
}

// TestProperty13_ComplianceReportingAndAuditing verifies that the project
// maintains the documentation and infrastructure required for compliance
// reporting and auditing:
//
//  1. docs/ directory exists and has at least one documentation sub-directory.
//  2. A monitoring module exists to support compliance dashboards and alerts.
//  3. At least 3 compliance-pack YAML files exist, covering multiple frameworks.
func TestProperty13_ComplianceReportingAndAuditing(t *testing.T) {
	t.Parallel()

	root := rootDir(t)

	// --- 1. docs/ must exist and contain at least one sub-directory ---
	docsDir := filepath.Join(root, "docs")
	if assertDirExists(t, docsDir, "docs/ directory for compliance documentation") {
		entries, err := os.ReadDir(docsDir)
		if err != nil {
			t.Fatalf("cannot read docs dir %s: %v", docsDir, err)
		}
		subDirCount := 0
		for _, e := range entries {
			if e.IsDir() {
				subDirCount++
			}
		}
		if subDirCount == 0 {
			t.Errorf(
				"docs/ directory has no sub-directories — expected at least one "+
					"(e.g. architecture/, compliance/, operations/) for structured documentation",
			)
		}
	}

	// --- 2. Monitoring module for compliance dashboards ---
	monitoringMain := filepath.Join(root, "modules", "management", "monitoring", "main.tf")
	assertFileExists(t, monitoringMain,
		"monitoring module main.tf — required for compliance reporting dashboards and alerting")

	// --- 3. At least 3 compliance-pack YAML files ---
	packsDir := filepath.Join(root, "policies", "compliance-packs")
	if assertDirExists(t, packsDir, "policies/compliance-packs/ directory") {
		entries, err := os.ReadDir(packsDir)
		if err != nil {
			t.Fatalf("cannot read compliance-packs dir %s: %v", packsDir, err)
		}
		yamlCount := 0
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml") {
				yamlCount++
			}
		}
		if yamlCount < 3 {
			t.Errorf(
				"policies/compliance-packs/ contains only %d YAML file(s) — at least 3 are "+
					"required to cover NCSC, UK GDPR, and Cyber Essentials frameworks (found %d)",
				yamlCount, yamlCount,
			)
		}
	}
}

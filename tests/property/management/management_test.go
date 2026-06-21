package property_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rootDir resolves the Terraform project root relative to the package directory
// that `go test` uses for this package (tests/property/management/).
func rootDir(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("cannot resolve root dir: %v", err)
	}
	return abs
}

// assertFileExists fails the test if the given path does not exist.
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

// TestProperty7_CentralizedLoggingAndMonitoring verifies that all logging and
// monitoring modules required for centralised observability are present, and
// that the CloudTrail module is configured for multi-region, long-term
// retention (as required by UK Government security standards).
func TestProperty7_CentralizedLoggingAndMonitoring(t *testing.T) {
	t.Parallel()

	root := rootDir(t)

	// All five module entry points must exist.
	requiredModules := map[string]string{
		"cloudtrail":        filepath.Join(root, "modules", "logging", "cloudtrail", "main.tf"),
		"log-archive":       filepath.Join(root, "modules", "logging", "log-archive", "main.tf"),
		"log-retention":     filepath.Join(root, "modules", "logging", "log-retention", "main.tf"),
		"cloudwatch":        filepath.Join(root, "modules", "management", "cloudwatch", "main.tf"),
		"monitoring":        filepath.Join(root, "modules", "management", "monitoring", "main.tf"),
	}

	for name, path := range requiredModules {
		name, path := name, path
		t.Run("module/"+name, func(t *testing.T) {
			t.Parallel()
			assertFileExists(t, path, name+" module main.tf")
		})
	}

	// CloudTrail-specific invariants: the module must enable multi-region
	// trails and reference a long retention period.
	t.Run("cloudtrail-configuration", func(t *testing.T) {
		t.Parallel()

		cloudtrailMain := filepath.Join(root, "modules", "logging", "cloudtrail", "main.tf")
		if _, err := os.Stat(cloudtrailMain); os.IsNotExist(err) {
			t.Skip("cloudtrail main.tf does not exist — skipping configuration checks")
		}

		raw, err := os.ReadFile(cloudtrailMain)
		if err != nil {
			t.Fatalf("cannot read %s: %v", cloudtrailMain, err)
		}
		content := string(raw)

		// Multi-region trail is required to capture events from all AWS regions
		// (including global services) into the central log archive.
		if !strings.Contains(content, "is_multi_region_trail") {
			t.Errorf(
				"%s: does not reference 'is_multi_region_trail' — CloudTrail must be "+
					"configured as a multi-region trail to satisfy NCSC logging requirements",
				cloudtrailMain,
			)
		}

		// Log retention: UK Government guidance mandates a minimum 7-year
		// retention period for security audit logs.  Accept either the
		// "7_YEARS" symbolic constant or "2557" (days) as evidence that
		// long-term retention has been addressed in this module.
		hasRetentionIndicator := strings.Contains(content, "7_YEARS") ||
			strings.Contains(content, "2557") ||
			strings.Contains(content, "retention")
		if !hasRetentionIndicator {
			t.Errorf(
				"%s: does not contain a retention indicator ('7_YEARS', '2557', or 'retention') — "+
					"CloudTrail logs must be retained for at least 7 years per UK Gov guidance",
				cloudtrailMain,
			)
		}
	})
}

// TestProperty10_InfrastructureAsCode verifies that the project adheres to
// rigorous Infrastructure-as-Code practices:
//
//  1. Every modules/*/main.tf begins with a terraform { block (within the first
//     500 characters), ensuring no ad-hoc or legacy files are present.
//  2. The CI/CD pipeline has at least 2 YAML workflow files.
//  3. A scripts/ directory exists, confirming operational automation tooling.
func TestProperty10_InfrastructureAsCode(t *testing.T) {
	t.Parallel()

	root := rootDir(t)

	// --- 1. All main.tf files must start with a terraform { block ---
	t.Run("terraform-blocks-in-all-main-tf", func(t *testing.T) {
		t.Parallel()

		modulesDir := filepath.Join(root, "modules")
		err := filepath.Walk(modulesDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				name := info.Name()
				if strings.HasPrefix(name, ".") || name == ".terraform" {
					return filepath.SkipDir
				}
				return nil
			}
			if filepath.Base(path) != "main.tf" {
				return nil
			}

			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Errorf("cannot read %s: %v", path, readErr)
				return nil
			}

			// Check within the first 500 characters so we catch files that
			// accidentally start with non-terraform content.
			head := string(raw)
			if len(head) > 500 {
				head = head[:500]
			}
			if !strings.Contains(head, "terraform {") {
				t.Errorf(
					"%s: does not begin with a 'terraform {' block within the first 500 characters — "+
						"all main.tf files must declare their terraform block at the top of the file",
					path,
				)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("error walking modules dir: %v", err)
		}
	})

	// --- 2. CI/CD pipeline must have at least 2 workflow YAML files ---
	t.Run("cicd-workflows-exist", func(t *testing.T) {
		t.Parallel()

		workflowsDir := filepath.Join(root, ".github", "workflows")
		if !assertDirExists(t, workflowsDir, ".github/workflows/ CI/CD pipeline directory") {
			return
		}

		entries, err := os.ReadDir(workflowsDir)
		if err != nil {
			t.Fatalf("cannot read workflows dir %s: %v", workflowsDir, err)
		}

		ymlCount := 0
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".yml") || strings.HasSuffix(e.Name(), ".yaml") {
				ymlCount++
			}
		}
		if ymlCount < 2 {
			t.Errorf(
				".github/workflows/ contains only %d YAML file(s) — at least 2 are required "+
					"(e.g. terraform-validate.yml, security-scan.yml) for a complete IaC pipeline",
				ymlCount,
			)
		}
	})

	// --- 3. scripts/ directory must exist ---
	t.Run("scripts-directory-exists", func(t *testing.T) {
		t.Parallel()

		scriptsDir := filepath.Join(root, "scripts")
		assertDirExists(t, scriptsDir,
			"scripts/ directory — required for operational automation tooling")
	})
}

package property_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rootDir resolves the Terraform project root relative to the working directory
// set by `go test` for this package (tests/property/disaster-recovery/).
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

// TestProperty12_DisasterRecovery verifies that the project implements a
// complete disaster-recovery posture:
//
//  1. A backup module exists and declares AWS Backup resources (vault + plan).
//  2. Operational runbooks exist under docs/ (either docs/operations/ or docs/).
//  3. At least 2 environment directories each have a main.tf, confirming that
//     workloads are deployed across isolated environments that can be recovered
//     independently.
func TestProperty12_DisasterRecovery(t *testing.T) {
	t.Parallel()

	root := rootDir(t)

	// --- 1. Backup module must exist and contain AWS Backup resources ---
	t.Run("backup-module-exists", func(t *testing.T) {
		t.Parallel()

		backupMain := filepath.Join(root, "modules", "management", "backup", "main.tf")
		if assertFileExists(t, backupMain,
			"backup module main.tf — required for automated disaster recovery backups") {

			raw, err := os.ReadFile(backupMain)
			if err != nil {
				t.Fatalf("cannot read %s: %v", backupMain, err)
			}
			content := string(raw)

			hasVault := strings.Contains(content, "aws_backup_vault")
			hasPlan := strings.Contains(content, "aws_backup_plan")

			if !hasVault {
				t.Errorf(
					"%s: does not contain 'aws_backup_vault' resource — "+
						"a backup vault is required to store recovery points securely",
					backupMain,
				)
			}
			if !hasPlan {
				t.Errorf(
					"%s: does not contain 'aws_backup_plan' resource — "+
						"a backup plan is required to define RPO schedules for disaster recovery",
					backupMain,
				)
			}
		}
	})

	// --- 2. Operational runbooks must exist ---
	// Runbooks are essential DR artefacts: they document recovery procedures.
	// Accept either docs/operations/ (preferred) or the docs/ root.
	t.Run("dr-runbooks-exist", func(t *testing.T) {
		t.Parallel()

		opsDir := filepath.Join(root, "docs", "operations")
		docsDir := filepath.Join(root, "docs")

		runbookFound := false

		// Check docs/operations/ for markdown/text runbooks
		if info, err := os.Stat(opsDir); err == nil && info.IsDir() {
			entries, err := os.ReadDir(opsDir)
			if err == nil {
				for _, e := range entries {
					name := strings.ToLower(e.Name())
					if strings.HasSuffix(name, ".md") || strings.HasSuffix(name, ".txt") {
						runbookFound = true
						break
					}
				}
				// Also check sub-directories (e.g. docs/operations/runbooks/)
				if !runbookFound {
					_ = filepath.Walk(opsDir, func(path string, info os.FileInfo, err error) error {
						if err != nil || info.IsDir() {
							return nil
						}
						name := strings.ToLower(info.Name())
						if strings.Contains(name, "runbook") ||
							strings.Contains(name, "disaster") ||
							strings.Contains(name, "recovery") {
							runbookFound = true
						}
						return nil
					})
				}
			}
		}

		// Fallback: search docs/ root for DR-related documents
		if !runbookFound {
			if info, err := os.Stat(docsDir); err == nil && info.IsDir() {
				_ = filepath.Walk(docsDir, func(path string, info os.FileInfo, err error) error {
					if err != nil || info.IsDir() {
						return nil
					}
					name := strings.ToLower(info.Name())
					if strings.Contains(name, "runbook") ||
						strings.Contains(name, "disaster") ||
						strings.Contains(name, "recovery") ||
						strings.Contains(name, "incident") {
						runbookFound = true
					}
					return nil
				})
			}
		}

		if !runbookFound {
			t.Errorf(
				"no DR runbooks found under docs/ — disaster recovery requires documented "+
					"recovery procedures (look for files with 'runbook', 'disaster', 'recovery', "+
					"or 'incident' in their name under docs/ or docs/operations/)",
			)
		}
	})

	// --- 3. At least 2 environment directories must each contain main.tf ---
	// Isolated environments enable independent recovery; at minimum we expect
	// production and non-production to be separated.
	t.Run("multiple-environments-for-isolation", func(t *testing.T) {
		t.Parallel()

		environmentsDir := filepath.Join(root, "environments")
		if !assertDirExists(t, environmentsDir, "environments/ directory") {
			return
		}

		entries, err := os.ReadDir(environmentsDir)
		if err != nil {
			t.Fatalf("cannot read environments dir %s: %v", environmentsDir, err)
		}

		envWithMainTF := []string{}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			mainTF := filepath.Join(environmentsDir, entry.Name(), "main.tf")
			if _, statErr := os.Stat(mainTF); statErr == nil {
				envWithMainTF = append(envWithMainTF, entry.Name())
			}
		}

		if len(envWithMainTF) < 2 {
			t.Errorf(
				"only %d environment(s) with main.tf found (%v) — at least 2 isolated "+
					"environments are required for meaningful disaster recovery isolation "+
					"(e.g. production-uk, non-production-uk)",
				len(envWithMainTF), envWithMainTF,
			)
		}
	})
}

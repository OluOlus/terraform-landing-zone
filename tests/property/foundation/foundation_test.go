package property_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rootDir returns the absolute path to the Terraform project root, two levels
// above the tests/property/foundation/ directory where this file lives.
func rootDir(t *testing.T) string {
	t.Helper()
	// __file__ equivalent: resolve from the working directory set by `go test`.
	// `go test` sets cwd to the package directory, so "../../.." reaches the root.
	abs, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("cannot resolve root dir: %v", err)
	}
	return abs
}

// walkTF calls fn for every *.tf file under dir, skipping hidden dirs and
// .terraform cache directories.
func walkTF(t *testing.T, dir string, fn func(path, content string)) {
	t.Helper()
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
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
		if !strings.HasSuffix(path, ".tf") {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Errorf("cannot read %s: %v", path, readErr)
			return nil
		}
		fn(path, string(raw))
		return nil
	})
	if err != nil {
		t.Fatalf("error walking %s: %v", dir, err)
	}
}

// TestProperty1_MultiAccountFoundationIntegrity verifies that every
// subdirectory of modules/avm-foundation/ contains the three required
// Terraform files: main.tf, variables.tf, and outputs.tf.
func TestProperty1_MultiAccountFoundationIntegrity(t *testing.T) {
	t.Parallel()

	avmDir := filepath.Join(rootDir(t), "modules", "avm-foundation")

	entries, err := os.ReadDir(avmDir)
	if err != nil {
		t.Fatalf("cannot read avm-foundation dir %s: %v", avmDir, err)
	}

	requiredFiles := []string{"main.tf", "variables.tf", "outputs.tf"}

	foundModules := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		foundModules++
		modPath := filepath.Join(avmDir, entry.Name())
		for _, required := range requiredFiles {
			filePath := filepath.Join(modPath, required)
			if _, statErr := os.Stat(filePath); os.IsNotExist(statErr) {
				t.Errorf(
					"avm-foundation module %q is missing required file %q (expected at %s)",
					entry.Name(), required, filePath,
				)
			}
		}
	}

	if foundModules == 0 {
		t.Errorf("no subdirectories found in %s — expected at least one AVM module", avmDir)
	}
}

// TestProperty2_AVMModulesCompliance verifies that every main.tf file under
// modules/ contains a terraform { block and a required_version constraint,
// ensuring all modules declare their minimum Terraform version requirement.
func TestProperty2_AVMModulesCompliance(t *testing.T) {
	t.Parallel()

	modulesDir := filepath.Join(rootDir(t), "modules")

	mainTFFiles := []string{}
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
		if filepath.Base(path) == "main.tf" {
			mainTFFiles = append(mainTFFiles, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("error walking modules dir: %v", err)
	}

	if len(mainTFFiles) == 0 {
		t.Fatal("no main.tf files found under modules/ — cannot validate AVM compliance")
	}

	for _, path := range mainTFFiles {
		path := path // capture for parallel sub-test
		relPath, _ := filepath.Rel(modulesDir, path)
		t.Run(relPath, func(t *testing.T) {
			t.Parallel()
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("cannot read %s: %v", path, err)
			}
			content := string(raw)

			if !strings.Contains(content, "terraform {") {
				t.Errorf("%s: missing required 'terraform {' block", path)
			}
			if !strings.Contains(content, "required_version") {
				t.Errorf("%s: missing required 'required_version' constraint in terraform block", path)
			}
		})
	}
}

// TestProperty11_MandatoryResourceTagging verifies that no Terraform file
// contains an empty tags block (tags = {}) and that files defining AWS
// resources reference a common_tags variable for consistent tagging.
func TestProperty11_MandatoryResourceTagging(t *testing.T) {
	t.Parallel()

	modulesDir := filepath.Join(rootDir(t), "modules")

	walkTF(t, modulesDir, func(path, content string) {
		// An empty tags = {} means the resource is intentionally untagged,
		// which violates the mandatory tagging policy.
		if strings.Contains(content, "tags = {}") {
			t.Errorf(
				"%s: contains empty 'tags = {}' block — all resources must use common_tags",
				path,
			)
		}

		// Files that declare aws_ resources must reference common_tags to
		// ensure the organisation-wide mandatory tags are applied.
		if strings.Contains(content, "resource \"aws_") {
			if !strings.Contains(content, "common_tags") &&
				!strings.Contains(content, "var.common_tags") &&
				!strings.Contains(content, "local.common_tags") &&
				!strings.Contains(content, "merge(") {
				t.Errorf(
					"%s: defines AWS resources but does not reference common_tags — "+
						"all AWS resources must include mandatory tags via common_tags",
					path,
				)
			}
		}
	})
}

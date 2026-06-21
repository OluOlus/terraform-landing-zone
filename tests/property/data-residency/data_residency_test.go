package property_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// disallowedRegions lists AWS regions that must never appear in UK Landing Zone
// Terraform source.  Only eu-west-2 (London) and eu-west-1 (Ireland) are
// permitted for workloads; us-east-1 is tolerated exclusively for global
// services (IAM, Route 53, CloudFront) and is handled by those services'
// own modules.
var disallowedRegions = []string{
	"us-east-2",
	"us-west-1",
	"us-west-2",
	"ap-southeast-1",
	"ap-southeast-2",
	"ap-northeast-1",
	"eu-central-1",
	"eu-north-1",
	"eu-west-3",
}

// rootDir resolves the Terraform project root relative to the cwd that
// `go test` sets (i.e. the directory of this package).
func rootDir(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("cannot resolve root dir: %v", err)
	}
	return abs
}

// walkTF invokes fn for every *.tf file found under dir, skipping hidden
// directories and .terraform cache directories.
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

// TestProperty3_UKDataResidency asserts that no Terraform file in modules/ or
// environments/ hard-codes a region that is outside the permitted UK set.
// Regions are matched as quoted string literals (e.g. "us-east-2") to avoid
// false positives from comments or variable names.
func TestProperty3_UKDataResidency(t *testing.T) {
	t.Parallel()

	root := rootDir(t)
	searchRoots := []string{
		filepath.Join(root, "modules"),
		filepath.Join(root, "environments"),
	}

	for _, searchRoot := range searchRoots {
		if _, err := os.Stat(searchRoot); os.IsNotExist(err) {
			t.Errorf("expected directory does not exist: %s", searchRoot)
			continue
		}

		walkTF(t, searchRoot, func(path, content string) {
			for _, region := range disallowedRegions {
				// Match the region as a quoted string literal to avoid
				// false positives from comments or variable descriptions.
				quoted := `"` + region + `"`
				if strings.Contains(content, quoted) {
					t.Errorf(
						"data residency violation: %s contains disallowed region %s — "+
							"only eu-west-2 and eu-west-1 are permitted for UK data residency",
						path, region,
					)
				}
			}
		})
	}
}

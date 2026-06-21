package property_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rootDir resolves the Terraform project root from the package working directory
// that `go test` sets for this package (tests/property/networking/).
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

// TestProperty8_HubSpokeNetworkArchitecture verifies that the hub-and-spoke
// network architecture is fully represented in the source tree.  It checks:
//
//  1. Transit Gateway module exists (the hub).
//  2. Network Firewall module exists (centralised traffic inspection).
//  3. DNS module exists (centralised DNS resolution).
//  4. A networking environment wires these together via main.tf.
//  5. The networking environment's tfvars example uses the expected hub CIDR
//     (10.40.0.0/16) defined in the architecture documentation.
func TestProperty8_HubSpokeNetworkArchitecture(t *testing.T) {
	t.Parallel()

	root := rootDir(t)

	// --- 1. Hub module: Transit Gateway ---
	tgwMain := filepath.Join(root, "modules", "networking", "transit-gateway", "main.tf")
	assertFileExists(t, tgwMain,
		"Transit Gateway main.tf — required as the hub in hub-and-spoke topology")

	// --- 2. Centralised traffic inspection: Network Firewall ---
	nfwMain := filepath.Join(root, "modules", "networking", "network-firewall", "main.tf")
	assertFileExists(t, nfwMain,
		"Network Firewall main.tf — required for centralised traffic inspection")

	// --- 3. Centralised DNS ---
	dnsMain := filepath.Join(root, "modules", "networking", "dns", "main.tf")
	assertFileExists(t, dnsMain,
		"DNS module main.tf — required for centralised DNS resolution across spoke VPCs")

	// --- 4. Networking environment entry point ---
	netEnvMain := filepath.Join(root, "environments", "networking", "main.tf")
	assertFileExists(t, netEnvMain,
		"environments/networking/main.tf — the environment that deploys the hub network")

	// --- 5. Hub CIDR consistency check ---
	// The architecture specifies 10.40.0.0/16 as the hub network CIDR.
	// The tfvars example must reflect this to keep documentation in sync with code.
	tfvarsExample := filepath.Join(root, "environments", "networking", "terraform.tfvars.example")
	if assertFileExists(t, tfvarsExample, "networking environment tfvars example") {
		raw, err := os.ReadFile(tfvarsExample)
		if err != nil {
			t.Fatalf("cannot read %s: %v", tfvarsExample, err)
		}
		if !strings.Contains(string(raw), "10.40.0.0/16") {
			t.Errorf(
				"%s: does not contain the expected hub network CIDR '10.40.0.0/16' — "+
					"the hub CIDR must match the architecture specification",
				tfvarsExample,
			)
		}
	}
}

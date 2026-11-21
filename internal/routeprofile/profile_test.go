package routeprofile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"exitnode/internal/protocol"
)

func TestSelectionValidatesExactDomain(t *testing.T) {
	for _, item := range []string{"https://allowed.example", "allowed.example\nEXITNODE_ROUTE_RELAY=other", "*.allowed.example", "127.0.0.1"} {
		if ValidDomain(item) {
			t.Fatalf("accepted invalid domain %q", item)
		}
	}
	if !ValidDomain("allowed.example") {
		t.Fatal("expected a valid hostname")
	}
	policy := protocol.Policy{Domains: []string{"allowed.example"}}
	if !allows(policy, "allowed.example") || allows(policy, "sub.allowed.example") || allows(policy, "private.example") {
		t.Fatal("route selection exceeded explicitly offered domains")
	}
}

func TestSelectWritesOnlyDomain(t *testing.T) {
	source := []byte("EXITNODE_ROUTE_DOMAIN=one.example\nEXITNODE_ROUTE_OWNER=owner\nEXITNODE_ROUTE_RELAY=relay.example:443\n")
	path := filepath.Join(t.TempDir(), "route.env")
	if err := os.WriteFile(path, source, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeDomain(path, source, "two.example"); err != nil {
		t.Fatal(err)
	}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(string(source), "DOMAIN=one.example", "DOMAIN=two.example", 1)
	if string(updated) != want {
		t.Fatalf("unexpected profile update %q", updated)
	}
}

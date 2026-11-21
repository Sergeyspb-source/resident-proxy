package egress

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSettingsPreserveLegacyAndRejectInvalidMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "egress-mode")
	if mode, err := Load(path); mode != System || err != nil {
		t.Fatalf("legacy mode = %q, %v", mode, err)
	}
	if err := Save(path, "unsupported"); err == nil {
		t.Fatal("invalid mode was saved")
	}
	if err := os.WriteFile(path, []byte("invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("invalid saved mode fell back to a permissive policy")
	}
	if err := Save(path, System); err != nil {
		t.Fatal(err)
	}
	if got, err := Load(path); got != System || err != nil {
		t.Fatalf("saved mode = %q, %v", got, err)
	}
}

func TestDirectRejectsUnknownRoute(t *testing.T) {
	if conn, path, err := Dial(context.Background(), Direct, "cannot-resolve.invalid:443"); conn != nil ||
		path.Kind != Unknown || !errors.Is(err, ErrDirectUnavailable) {
		t.Fatalf("unverified destination was not blocked: %+v, %v", path, err)
	}
}

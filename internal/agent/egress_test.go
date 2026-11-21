package agent

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"

	"exitnode/internal/egress"
)

func TestEgressModeChangeCancelsActiveAndPendingStreams(t *testing.T) {
	old, next := egress.Direct, egress.System
	if egress.Supported() {
		old, next = egress.System, egress.Direct
	}
	path := filepath.Join(t.TempDir(), "egress-mode")
	if err := os.WriteFile(path, []byte(old+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &Agent{log: log.New(io.Discard, "", 0), egressMode: old, egressPath: path}
	a.SetEnabled(true)
	pending := testAgentStream(t, a, "one")
	active := testAgentStream(t, a, "two")
	testAttachTarget(t, a, active)
	if err := a.SetEgressMode(next); err != nil {
		t.Fatal(err)
	}
	if pending.ctx.Err() == nil || active.ctx.Err() == nil {
		t.Fatal("one or more old streams survived the mode change")
	}
	if mode, err := egress.Load(path); mode != next || err != nil {
		t.Fatalf("persisted mode = %q, %v", mode, err)
	}
}

func TestEgressSaveFailureKeepsPolicy(t *testing.T) {
	a := &Agent{
		log: log.New(io.Discard, "", 0), egressMode: egress.Direct,
		egressPath: filepath.Join(t.TempDir(), "missing", "egress-mode"),
	}
	a.SetEnabled(true)
	flow := testAgentStream(t, a, "key")
	if err := a.SetEgressMode(egress.System); err == nil {
		t.Fatal("mode change unexpectedly succeeded without persistence")
	}
	if mode, _ := a.currentEgress(); mode != egress.Direct || flow.ctx.Err() != nil {
		t.Fatal("a failed change modified the policy or canceled an active request")
	}
}

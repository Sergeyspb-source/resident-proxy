package agent

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"golang.org/x/time/rate"

	"exitnode/internal/limits"
	"exitnode/internal/protocol"
)

func TestRemoveKeyStopsOnlyItsStreams(t *testing.T) {
	a := &Agent{
		log:  log.New(io.Discard, "", 0),
		keys: []limits.AccessKey{{ID: "first"}, {ID: "second"}},
	}
	a.SetEnabled(true)

	first := testAgentStream(t, a, "first")
	pending := testAgentStream(t, a, "first")
	second := testAgentStream(t, a, "second")
	firstTarget := testAttachTarget(t, a, first)
	secondTarget := testAttachTarget(t, a, second)

	if err := a.RemoveKey("first"); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(first.ctx.Err(), context.Canceled) || !errors.Is(pending.ctx.Err(), context.Canceled) {
		t.Fatal("revocation must cancel active and pending requests for the removed key")
	}

	if _, err := firstTarget.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("revoked target read: got %v, want EOF", err)
	}
	if second.ctx.Err() != nil {
		t.Fatal("revoking one key canceled a different client")
	}

	go second.target.Write([]byte("x"))
	if _, err := io.ReadFull(secondTarget, make([]byte, 1)); err != nil {
		t.Fatalf("other client can no longer receive traffic: %v", err)
	}
}

func TestDisableThenEnableRejectsOldPendingStream(t *testing.T) {
	a := &Agent{}
	a.SetEnabled(true)
	pending := testAgentStream(t, a, "")
	active := testAgentStream(t, a, "first")
	target := testAttachTarget(t, a, active)

	a.SetEnabled(false)
	if !errors.Is(active.ctx.Err(), context.Canceled) {
		t.Fatal("disabling the node did not cancel the active connection")
	}

	if _, err := target.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("disabled target read: got %v, want EOF", err)
	}
	disabledConn, peer := net.Pipe()
	defer disabledConn.Close()
	defer peer.Close()
	if flow := a.beginStream(disabledConn); flow != nil {
		t.Fatal("disabled node accepted a new request")
	}
	a.SetEnabled(true)

	late, peerLate := net.Pipe()
	defer late.Close()
	defer peerLate.Close()
	if a.attachTarget(pending, late) {
		t.Fatal("a request from before disable was allowed to resume")
	}
	fresh := testAgentStream(t, a, "first")
	testAttachTarget(t, a, fresh)
}

func TestDisableUnblocksPendingE2E(t *testing.T) {
	a := &Agent{
		log:      log.New(io.Discard, "", 0),
		cfg:      Config{MaxSessions: 1},
		keys:     []limits.AccessKey{{ID: "first", Value: "local-test-only"}},
		limiters: make(map[string]*rate.Limiter),
	}
	a.SetEnabled(true)

	st, done := openTestStream(t, a, protocol.OpenRequest{KeyID: "first", Host: protocol.E2EHost})
	var rep protocol.Reply
	if err := protocol.ReadJSON(protocol.NewBufConn(st).R, &rep); err != nil || !rep.OK {
		t.Fatalf("could not start the local E2E handshake: %+v, %v", rep, err)
	}

	a.SetEnabled(false)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("disabling the node did not release the pending handshake")
	}
}

func TestAgentRequiresEncryptedTarget(t *testing.T) {
	a := &Agent{cfg: Config{MaxSessions: 1}}
	a.SetEnabled(true)
	st, _ := openTestStream(t, a, protocol.OpenRequest{Host: "example.invalid"})
	var rep protocol.Reply
	if err := protocol.ReadJSON(protocol.NewBufConn(st).R, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.OK || rep.Code != protocol.CodeNotAllowed {
		t.Fatalf("expected an encrypted-target requirement, got %+v", rep)
	}
}

func openTestStream(t *testing.T, a *Agent, req protocol.OpenRequest) (*yamux.Stream, <-chan error) {
	t.Helper()
	left, right := net.Pipe()
	t.Cleanup(func() { left.Close(); right.Close() })
	agentMux, err := yamux.Client(left, protocol.MuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { agentMux.Close() })
	relayMux, err := yamux.Server(right, protocol.MuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { relayMux.Close() })

	done := make(chan error, 1)
	go func() {
		st, err := agentMux.AcceptStream()
		if err == nil {
			a.handleStream(st)
		}
		done <- err
	}()
	st, err := relayMux.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	_ = st.SetDeadline(time.Now().Add(2 * time.Second))
	if err := protocol.WriteJSON(st, req); err != nil {
		t.Fatal(err)
	}
	return st, done
}

func testAgentStream(t *testing.T, a *Agent, keyID string) *agentStream {
	t.Helper()
	local, peer := net.Pipe()
	t.Cleanup(func() { local.Close(); peer.Close() })
	flow := a.beginStream(local)
	if flow == nil {
		t.Fatal("enabled node rejected a new stream")
	}
	a.stateMu.Lock()
	flow.keyID = keyID
	a.stateMu.Unlock()
	t.Cleanup(func() { a.finishStream(flow) })
	return flow
}

func testAttachTarget(t *testing.T, a *Agent, flow *agentStream) net.Conn {
	t.Helper()
	local, peer := net.Pipe()
	t.Cleanup(func() { local.Close(); peer.Close() })
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if !a.attachTarget(flow, local) {
		t.Fatal("a fresh stream refused its target")
	}
	return peer
}

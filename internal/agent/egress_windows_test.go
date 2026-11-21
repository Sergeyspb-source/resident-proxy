//go:build windows

package agent

import (
	"context"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"exitnode/internal/egress"
	"exitnode/internal/limits"
	"exitnode/internal/protocol"
	"exitnode/internal/secure"
)

// TestLiveAgentStrictEgress verifies the actual inner request path with an opt-in tunnel destination.
func TestLiveAgentStrictEgress(t *testing.T) {
	target := os.Getenv("EXITNODE_TEST_TUNNEL_ADDRESS")
	if target == "" {
		t.Skip("provide a tunnel destination")
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := NewGuard(portText)
	if err != nil {
		t.Fatal(err)
	}
	const testKey = "egress-test-secret-not-a-deployment-key"
	a := &Agent{
		cfg:   Config{Name: "test-owner", MaxSessions: 2},
		guard: guard, log: log.New(io.Discard, "", 0), egressMode: egress.Direct,
		keys: []limits.AccessKey{{ID: "paired", Value: testKey, Limits: limits.Values{Domains: host}}},
	}
	a.limiters = make(map[string]*rate.Limiter)
	a.SetEnabled(true)
	open := func(frame protocol.E2EConnect) *protocol.BufConn {
		t.Helper()
		stream, done := openTestStream(t, a, protocol.OpenRequest{Host: protocol.E2EHost, KeyID: "paired"})
		t.Cleanup(func() { <-done })
		outer := protocol.NewBufConn(stream)
		var ack protocol.Reply
		if err := protocol.ReadJSON(outer.R, &ack); err != nil || !ack.OK {
			t.Fatalf("outer denied: %+v %v", ack, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		sec, err := secure.Client(ctx, outer, testKey)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { sec.Close() })
		if err := protocol.WriteJSON(sec, frame); err != nil {
			t.Fatal(err)
		}
		return protocol.NewBufConn(sec)
	}

	data := open(protocol.E2EConnect{Host: host, Port: port})
	if n, err := data.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatal("strict tunnel request read unexpected data")
	}
	_, last := a.currentEgress()
	if last == nil || last.Kind != egress.Tunnel || last.Outcome != "blocked" || last.Interface == "" {
		t.Fatalf("missing blocked tunnel observation: %+v", last)
	}
	readPolicy := open(protocol.E2EConnect{Action: protocol.E2EPolicy})
	var policy protocol.Policy
	if err := protocol.ReadJSON(readPolicy.R, &policy); err != nil {
		t.Fatal(err)
	}
	if policy.EgressMode != egress.Direct || policy.LastEgress == nil ||
		policy.LastEgress.Outcome != "blocked" || policy.LastEgress.Interface != "" {
		t.Fatalf("invalid client policy: %+v", policy)
	}
	t.Logf("owner blocked %s through %s and published the result over inner TLS", host, last.Interface)
}

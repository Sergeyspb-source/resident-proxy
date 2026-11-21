package agent

import (
	"context"
	"io"
	"log"
	"testing"
	"time"

	"exitnode/internal/limits"
	"exitnode/internal/protocol"
	"exitnode/internal/secure"
)

func TestExhaustedKeyCanReadOnlyItsPolicy(t *testing.T) {
	now := time.Now()
	a := &Agent{
		log: log.New(io.Discard, "", 0),
		cfg: Config{Name: "owner", MaxSessions: 2},
		keys: []limits.AccessKey{
			{
				ID: "mine", Value: "first-test-only",
				Limits: limits.Values{Domains: "allowed.example, *.two.example", QuotaMB: 1, QuotaMonthMB: 2, RateKBps: 128},
				Day:    now.Format(dayLayout), Month: now.Format("2006-01"), Used: 1 << 20, UsedMonth: 1 << 20,
			},
			{ID: "other", Value: "other-test-only", Limits: limits.Values{Domains: "private.example"}},
		},
	}
	a.SetEnabled(true)
	stream, _ := openTestStream(t, a, protocol.OpenRequest{Host: protocol.E2EHost, KeyID: "mine"})
	bc := protocol.NewBufConn(stream)
	var rep protocol.Reply
	if err := protocol.ReadJSON(bc.R, &rep); err != nil || !rep.OK {
		t.Fatalf("outer stream: %+v, %v", rep, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tlsConn, err := secure.Client(ctx, bc, "first-test-only")
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteJSON(tlsConn, protocol.E2EConnect{Action: protocol.E2EPolicy}); err != nil {
		t.Fatal(err)
	}
	var got protocol.Policy
	if err := protocol.ReadJSON(protocol.NewBufConn(tlsConn).R, &got); err != nil {
		t.Fatal(err)
	}
	if got.Owner != "owner" || len(got.Domains) != 2 || got.Domains[0] != "allowed.example" ||
		got.Domains[1] != "two.example" || got.DayBytes != 1<<20 || got.DayUsed != 1<<20 ||
		got.MonthBytes != 2<<20 || got.MonthUsed != 1<<20 || got.RateKBps != 128 {
		t.Fatalf("published wrong policy: %+v", got)
	}
}

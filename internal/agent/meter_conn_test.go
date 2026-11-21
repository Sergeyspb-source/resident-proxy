package agent

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"exitnode/internal/limits"
)

func TestMeterConnSharesRateAcrossDirections(t *testing.T) {
	for _, uploadFirst := range []bool{true, false} {
		name := "download then upload"
		if uploadFirst {
			name = "upload then download"
		}
		t.Run(name, func(t *testing.T) {
			const burst = 64 << 10
			const chunk = 8 << 10
			meter, peer, in, out := newRateTestConn(t, rate.NewLimiter(chunk, burst))
			firstWriter, firstReader := net.Conn(meter), peer
			if uploadFirst {
				firstWriter, firstReader = firstReader, firstWriter
			}

			started := time.Now()
			transferRateTestBytes(t, firstWriter, firstReader, burst)
			transferRateTestBytes(t, firstReader, firstWriter, chunk)
			elapsed := time.Since(started)
			if elapsed < 750*time.Millisecond {
				t.Fatalf("opposite direction bypassed the shared limiter: %s", elapsed)
			}
			expectedIn, expectedOut := int64(chunk), int64(burst)
			if uploadFirst {
				expectedIn, expectedOut = expectedOut, expectedIn
			}
			if in.Load() != expectedIn || out.Load() != expectedOut {
				t.Fatalf("payload accounting mismatch: in=%d out=%d", in.Load(), out.Load())
			}
			t.Logf("transferred %d bytes in %s through an 8 KiB/s shared limiter", burst+chunk, elapsed.Round(time.Millisecond))
		})
	}
}

func TestMeterConnRevocationCancelsBothDirections(t *testing.T) {
	const chunk = 8 << 10
	a := &Agent{
		log:  log.New(io.Discard, "", 0),
		keys: []limits.AccessKey{{ID: "limited"}},
	}
	a.SetEnabled(true)
	limiter := rate.NewLimiter(1024, chunk)
	if !limiter.AllowN(time.Now(), chunk) {
		t.Fatal("could not drain the initial burst")
	}
	meter, peer, in, out := newRateTestConn(t, limiter)
	flow := a.beginStream(meter.Conn)
	if flow == nil {
		t.Fatal("enabled node rejected the stream")
	}
	a.stateMu.Lock()
	flow.keyID = "limited"
	a.stateMu.Unlock()
	t.Cleanup(func() { a.finishStream(flow) })
	meter.ctx, meter.cancel = flow.ctx, flow.cancel

	type result struct {
		n   int
		err error
	}
	read, write := make(chan result, 1), make(chan result, 1)
	go func() { _, _ = peer.Write(make([]byte, chunk)) }()
	go func() {
		n, err := meter.Read(make([]byte, chunk))
		read <- result{n, err}
	}()
	go func() {
		n, err := meter.Write(make([]byte, chunk))
		write <- result{n, err}
	}()

	deadline := time.Now().Add(time.Second)
	for limiter.Tokens() >= -chunk {
		if time.Now().After(deadline) {
			t.Fatal("both directions did not enter a pending rate wait")
		}
		time.Sleep(time.Millisecond)
	}
	if err := a.RemoveKey("limited"); err != nil {
		t.Fatal(err)
	}
	for _, ch := range []<-chan result{read, write} {
		select {
		case got := <-ch:
			if got.n != 0 || !errors.Is(got.err, context.Canceled) {
				t.Fatalf("revoked transfer returned %d bytes, %v", got.n, got.err)
			}
		case <-time.After(time.Second):
			t.Fatal("revocation did not wake a rate wait")
		}
	}
	if in.Load() != chunk || out.Load() != 0 {
		t.Fatalf("expected the already received bytes to count once: in=%d out=%d", in.Load(), out.Load())
	}
}

func newRateTestConn(t *testing.T, limiter *rate.Limiter) (*meterConn, net.Conn, *atomic.Int64, *atomic.Int64) {
	t.Helper()
	local, peer := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	t.Cleanup(func() { local.Close(); peer.Close() })
	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := local.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	in, out := new(atomic.Int64), new(atomic.Int64)
	meter := &meterConn{
		Conn:    local,
		ctx:     ctx,
		cancel:  cancel,
		limiter: limiter,
		onRead:  func(n int64) { in.Add(n) },
		onWrite: func(n int64) { out.Add(n) },
	}
	return meter, peer, in, out
}

func transferRateTestBytes(t *testing.T, writer, reader net.Conn, size int) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := writer.Write(make([]byte, size))
		done <- err
	}()
	if _, err := io.ReadFull(reader, make([]byte, size)); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

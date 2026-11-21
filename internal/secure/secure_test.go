package secure

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

const testInvitation = "test-invitation-from-the-local-fixture"

func TestRoundTrip(t *testing.T) {
	client, server := localTLS(t, testInvitation, testInvitation)
	if client.err != nil || server.err != nil {
		t.Fatalf("handshake: client %v, agent %v", client.err, server.err)
	}
	want := bytes.Repeat([]byte("exitnode "), 5000)
	transfer(t, client.conn, server.conn, want)
	transfer(t, server.conn, client.conn, want)
}

func TestWrongKey(t *testing.T) {
	for _, wrongPeer := range []string{"client", "agent"} {
		t.Run(wrongPeer, func(t *testing.T) {
			clientSecret, agentSecret := testInvitation, testInvitation
			if wrongPeer == "client" {
				clientSecret = "unrelated-invitation"
			} else {
				agentSecret = "unrelated-invitation"
			}
			client, server := localTLS(t, clientSecret, agentSecret)
			if client.err == nil || server.err == nil {
				t.Fatalf("mismatched invitation: client %v, agent %v", client.err, server.err)
			}
		})
	}
}

func TestSessionsDeriveDistinctSecrets(t *testing.T) {
	var last []byte
	for range 2 {
		client, server := localTLS(t, testInvitation, testInvitation)
		if client.err != nil || server.err != nil {
			t.Fatalf("handshake: client %v, agent %v", client.err, server.err)
		}
		cs, ss := client.conn.ConnectionState(), server.conn.ConnectionState()
		if cs.Version != tls.VersionTLS13 || cs.DidResume || ss.DidResume {
			t.Fatal("every stream must perform a fresh TLS 1.3 handshake")
		}
		clientSecret, err := cs.ExportKeyingMaterial("test-session-isolation", nil, 32)
		if err != nil {
			t.Fatal(err)
		}
		serverSecret, err := ss.ExportKeyingMaterial("test-session-isolation", nil, 32)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(clientSecret, serverSecret) || bytes.Equal(last, clientSecret) {
			t.Fatal("session secret must match its peer and differ from the previous session")
		}
		last = clientSecret
	}
}

type endpoint struct {
	conn *tls.Conn
	err  error
}

func localTLS(t *testing.T, clientSecret, agentSecret string) (endpoint, endpoint) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	_ = a.SetDeadline(deadline)
	_ = b.SetDeadline(deadline)
	done := make(chan endpoint, 1)
	go func() {
		conn, err := Server(ctx, b, agentSecret)
		if err != nil {
			_ = b.Close()
		}
		done <- endpoint{conn: conn, err: err}
	}()
	conn, err := Client(ctx, a, clientSecret)
	if err != nil {
		_ = a.Close()
	}
	return endpoint{conn: conn, err: err}, <-done
}

func transfer(t *testing.T, writer, reader net.Conn, want []byte) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := writer.Write(want)
		done <- err
	}()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("payload mismatch")
	}
}

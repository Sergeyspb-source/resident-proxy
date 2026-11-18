package secure

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	key := DeriveKey("test-key-value")

	ca, err := NewConn(a, key)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := NewConn(b, key)
	if err != nil {
		t.Fatal(err)
	}

	want := bytes.Repeat([]byte("exitnode "), 5000)
	done := make(chan error, 1)
	go func() {
		_, err := ca.Write(want)
		done <- err
	}()

	got := make([]byte, len(want))
	if _, err := io.ReadFull(cb, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("данные не совпали")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestWrongKey(t *testing.T) {
	a, b := net.Pipe()
	ca, _ := NewConn(a, DeriveKey("one"))
	cb, _ := NewConn(b, DeriveKey("two"))

	go ca.Write([]byte("secret"))
	buf := make([]byte, 16)
	if _, err := cb.Read(buf); err == nil {
		t.Fatal("чтение с чужим ключом должно падать")
	}
}

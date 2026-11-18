package agent

import "testing"

func TestTLSServerName(t *testing.T) {
	got, err := tlsServerName("proxy.example.com:8443", "")
	if err != nil || got != "proxy.example.com" {
		t.Fatalf("got %q, %v", got, err)
	}

	got, err = tlsServerName("203.0.113.10:8443", "proxy.example.com")
	if err != nil || got != "proxy.example.com" {
		t.Fatalf("override: got %q, %v", got, err)
	}

	if _, err := tlsServerName("без-порта", ""); err == nil {
		t.Fatal("адрес без порта должен давать ошибку")
	}
}

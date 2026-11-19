package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := &Manifest{Version: "1.2.3", Files: []File{{Name: "a.bin", Size: 7, SHA256: "abc"}}}
	if err := Sign(priv, m); err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, m); err != nil {
		t.Fatalf("подпись не прошла: %v", err)
	}

	m.Version = "1.2.4"
	if err := Verify(pub, m); err != ErrSignature {
		t.Fatalf("подмена версии не замечена: %v", err)
	}
}

func TestVerifyWithoutSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	m := &Manifest{Version: "1.0.0"}
	if err := Verify(pub, m); err != ErrSignature {
		t.Fatalf("ожидали ошибку подписи, получили %v", err)
	}
}

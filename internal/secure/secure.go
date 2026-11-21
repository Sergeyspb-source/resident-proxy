// Package secure establishes mutual TLS between a client and an exit agent.
package secure

import (
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"time"
)

const innerProtocol = "exitnode-e2e/2"

// #GPT: authenticate the agent using the invitation secret before sending the target.
func Client(ctx context.Context, conn net.Conn, invitation string) (*tls.Conn, error) {
	cfg, err := config(invitation, "client", "agent")
	if err != nil {
		return nil, err
	}
	// The peer has no public CA certificate. VerifyConnection always checks the pinned key.
	cfg.InsecureSkipVerify = true
	secure := tls.Client(conn, cfg)
	if err := secure.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return secure, nil
}

// #GPT: require the peer to prove possession of the client key in a fresh handshake.
func Server(ctx context.Context, conn net.Conn, invitation string) (*tls.Conn, error) {
	cfg, err := config(invitation, "agent", "client")
	if err != nil {
		return nil, err
	}
	cfg.ClientAuth = tls.RequireAnyClientCert
	secure := tls.Server(conn, cfg)
	if err := secure.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return secure, nil
}

// #GPT: pin the opposite role's key and disable resumption so each stream authenticates afresh.
func config(invitation, localRole, peerRole string) (*tls.Config, error) {
	localKey, err := identity(invitation, localRole)
	if err != nil {
		return nil, err
	}
	peerKey, err := identity(invitation, peerRole)
	if err != nil {
		return nil, err
	}
	localPub := localKey.Public().(ed25519.PublicKey)
	expectedPeer := peerKey.Public().(ed25519.PublicKey)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, localPub, localKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{innerProtocol},
		Certificates: []tls.Certificate{
			{Certificate: [][]byte{cert}, PrivateKey: localKey},
		},
		SessionTicketsDisabled: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if state.NegotiatedProtocol != innerProtocol || len(state.PeerCertificates) != 1 {
				return errors.New("exitnode: invalid inner TLS peer")
			}
			peer, ok := state.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
			if !ok || !expectedPeer.Equal(peer) {
				return errors.New("exitnode: inner TLS peer key mismatch")
			}
			return nil
		},
	}, nil
}

// #GPT: derive distinct identities from the full invitation, independently of the relay routing hash.
func identity(invitation, role string) (ed25519.PrivateKey, error) {
	if invitation == "" {
		return nil, errors.New("exitnode: empty invitation secret")
	}
	seed, err := hkdf.Key(sha256.New, []byte(invitation), nil, innerProtocol+"/identity/"+role, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

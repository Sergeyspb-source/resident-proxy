package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"
)

const (
	System = "system"
	Direct = "direct"

	Physical = "physical"
	Tunnel   = "tunnel"
	Unknown  = "unknown"
)

var ErrDirectUnavailable = errors.New("a direct interface could not be confirmed")

type Route struct {
	Kind      string
	Interface string
	index     uint32
	luid      uint64
}

// GPT: Classify the exact IP already resolved and checked by the destination guard.
func Lookup(address string) Route {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return Route{Kind: Unknown}
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return Route{Kind: Unknown}
	}
	return lookup(ip.Unmap())
}

// GPT: Bind a strict connection to the physical interface selected by the OS.
func Dial(ctx context.Context, mode, address string) (net.Conn, Route, error) {
	path := Lookup(address)
	dialer := net.Dialer{Timeout: 15 * time.Second}
	network := "tcp"
	if mode == Direct {
		if path.Kind != Physical {
			return nil, path, ErrDirectUnavailable
		}
		host, _, _ := net.SplitHostPort(address)
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return nil, path, ErrDirectUnavailable
		}
		network = "tcp6"
		if ip.Unmap().Is4() {
			network = "tcp4"
		}
		pin(&dialer, path, network)
	}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, path, err
	}
	current := Lookup(address)
	if mode == Direct && !path.SamePhysical(current) {
		_ = conn.Close()
		return nil, current, ErrDirectUnavailable
	}
	return conn, current, nil
}

func (r Route) SamePhysical(other Route) bool {
	return r.Kind == Physical && other.Kind == Physical && r.index == other.index && r.luid == other.luid
}

func validMode(mode string) bool { return mode == System || mode == Direct }

func readMode(text string) (string, error) {
	mode := strings.TrimSpace(text)
	if !validMode(mode) {
		return "", errors.New("invalid saved egress mode")
	}
	return mode, nil
}

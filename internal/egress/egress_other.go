//go:build !windows

package egress

import (
	"net"
	"net/netip"
)

func Supported() bool { return false }

func lookup(netip.Addr) Route { return Route{Kind: Unknown} }

func pin(*net.Dialer, Route, string) {}

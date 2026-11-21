//go:build windows

package egress

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestClassifiesPhysicalAndVirtualAdapters(t *testing.T) {
	physical := windows.MibIfRow2{
		InterfaceLuid: 42, Type: windows.IF_TYPE_ETHERNET_CSMACD,
		OperStatus: windows.IfOperStatusUp, InterfaceAndOperStatusFlags: 1,
	}
	if got := classify(physical, "ethernet"); got != Physical {
		t.Fatalf("hardware adapter = %s", got)
	}
	virtual := physical
	virtual.InterfaceAndOperStatusFlags = 0
	if got := classify(virtual, "xray_tun wintun tunnel"); got != Tunnel {
		t.Fatalf("Wintun route = %s", got)
	}
	if got := classify(virtual, "virtual switch"); got != Unknown {
		t.Fatalf("unknown virtual adapter = %s", got)
	}
	physical.InterfaceAndOperStatusFlags |= 1 << 1
	if got := classify(physical, "ethernet with filter flag"); got != Unknown {
		t.Fatalf("filter route = %s", got)
	}
}

// TestLiveWindowsEgress is an opt-in acceptance check with operator-selected destinations.
func TestLiveWindowsEgress(t *testing.T) {
	tunnel, physical := os.Getenv("EXITNODE_TEST_TUNNEL_ADDRESS"), os.Getenv("EXITNODE_TEST_PHYSICAL_ADDRESS")
	if tunnel == "" || physical == "" {
		t.Skip("provide tunnel and physical acceptance addresses")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if conn, route, err := Dial(ctx, Direct, tunnel); conn != nil || route.Kind != Tunnel ||
		!errors.Is(err, ErrDirectUnavailable) {
		t.Fatalf("expected strict rejection on tunnel route: %+v (%v)", route, err)
	} else {
		t.Logf("strict mode rejected %s through %s", tunnel, route.Interface)
	}
	conn, route, err := Dial(ctx, Direct, physical)
	if err != nil {
		t.Fatalf("strict physical connect: %+v (%v)", route, err)
	}
	_ = conn.Close()
	t.Logf("strict socket connected to %s pinned to %s", physical, route.Interface)
}

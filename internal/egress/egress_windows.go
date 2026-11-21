//go:build windows

package egress

import (
	"math/bits"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

func Supported() bool { return true }

// GPT: Confirm only operational hardware Ethernet and Wi-Fi as physical routes.
func lookup(ip netip.Addr) Route {
	var socket windows.Sockaddr = &windows.SockaddrInet6{Addr: ip.As16()}
	if ip.Is4() {
		socket = &windows.SockaddrInet4{Addr: ip.As4()}
	}
	var index uint32
	if err := windows.GetBestInterfaceEx(socket, &index); err != nil || index == 0 {
		return Route{Kind: Unknown}
	}
	row := windows.MibIfRow2{InterfaceIndex: index}
	if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormalWithoutStatistics, &row); err != nil {
		return Route{Kind: Unknown}
	}
	name := windows.UTF16ToString(row.Alias[:])
	description := strings.ToLower(name + " " + windows.UTF16ToString(row.Description[:]))
	return Route{Kind: classify(row, description), Interface: name, index: index, luid: row.InterfaceLuid}
}

func classify(row windows.MibIfRow2, description string) string {
	if row.Type == windows.IF_TYPE_TUNNEL || row.TunnelType != 0 {
		return Tunnel
	}
	for _, name := range []string{"wintun", "wireguard", "xray_tun", "tap-windows", "openvpn", "tailscale"} {
		if strings.Contains(description, name) {
			return Tunnel
		}
	}
	const hardware = 1 << 0
	const filterOrUnavailable = 1<<1 | 1<<4 | 1<<5 | 1<<7
	if row.InterfaceAndOperStatusFlags&hardware == 0 ||
		row.InterfaceAndOperStatusFlags&filterOrUnavailable != 0 ||
		row.OperStatus != windows.IfOperStatusUp || row.InterfaceLuid == 0 {
		return Unknown
	}
	if row.Type == windows.IF_TYPE_ETHERNET_CSMACD || row.Type == windows.IF_TYPE_IEEE80211 {
		return Physical
	}
	return Unknown
}

// GPT: Winsock expects IPv4 interface indices in network byte order and IPv6 in host order.
func pin(dialer *net.Dialer, path Route, network string) {
	const unicastInterface = 31
	level := windows.IPPROTO_IPV6
	index := path.index
	if network == "tcp4" {
		level = windows.IPPROTO_IP
		index = bits.ReverseBytes32(index)
	}
	dialer.Control = func(_, _ string, raw syscall.RawConn) error {
		var optErr error
		if err := raw.Control(func(fd uintptr) {
			optErr = windows.SetsockoptInt(windows.Handle(fd), level, unicastInterface, int(index))
		}); err != nil {
			return err
		}
		return optErr
	}
}

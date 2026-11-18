package agent

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"exitnode/internal/limits"
	"exitnode/internal/protocol"
)

// Guard решает, куда агенту разрешено подключаться.
// Главная задача — не дать клиенту попасть в локальную сеть коллеги
// (роутер, принтер, NAS) и в служебные диапазоны.
type Guard struct {
	ports map[int]bool
	any   bool
}

func NewGuard(spec string) (*Guard, error) {
	g := &Guard{ports: make(map[int]bool)}
	spec = strings.TrimSpace(spec)
	if spec == "" {
		spec = "80,443"
	}
	if strings.EqualFold(spec, "any") {
		g.any = true
		return g, nil
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("неверный порт: %q", part)
		}
		g.ports[p] = true
	}
	if len(g.ports) == 0 {
		return nil, fmt.Errorf("список портов пуст")
	}
	return g, nil
}

func (g *Guard) allowed(port int) bool {
	return g.any || g.ports[port]
}

// allowedHost проверяет домен или IP по белому списку конкретного ключа.
// GPT: "example.com" разрешает и сам домен, и любые поддомены —
// иначе пришлось бы перечислять каждый поддомен вручную.
func (g *Guard) allowedHost(spec, host string) bool {
	domains := limits.DomainList(spec)
	if len(domains) == 0 {
		return true
	}

	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if net.ParseIP(h) != nil {
		for _, d := range domains {
			if d == h {
				return true
			}
		}
		return false
	}
	for _, d := range domains {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

// Resolve проверяет порт и домен, резолвит имя и возвращает уже проверенный IP.
// GPT: агент сам делает DNS и сам подключается по IP, а не по имени —
// так исключается DNS-rebinding, при котором домен сначала отдаёт
// публичный адрес, а на момент соединения — локальный.
func (g *Guard) Resolve(ctx context.Context, host string, port int, domains string) (string, error) {
	if !g.allowed(port) {
		return "", &protocol.OpenError{
			Code:    protocol.CodeNotAllowed,
			Message: fmt.Sprintf("порт %d запрещён настройками узла", port),
		}
	}
	if host == "" {
		return "", &protocol.OpenError{Code: protocol.CodeUnreachable, Message: "пустой адрес"}
	}
	if !g.allowedHost(domains, host) {
		return "", &protocol.OpenError{
			Code:    protocol.CodeNotAllowed,
			Message: "домен не входит в список разрешённых: " + host,
		}
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", &protocol.OpenError{Code: protocol.CodeUnreachable, Message: "не удалось разрешить имя"}
	}
	if len(ips) == 0 {
		return "", &protocol.OpenError{Code: protocol.CodeUnreachable, Message: "имя не разрешилось ни в один адрес"}
	}
	for _, ip := range ips {
		if isBlocked(ip.IP) {
			return "", &protocol.OpenError{
				Code:    protocol.CodeNotAllowed,
				Message: "адрес в локальной или служебной сети: " + ip.IP.String(),
			}
		}
	}
	return net.JoinHostPort(ips[0].IP.String(), strconv.Itoa(port)), nil
}

// isBlocked отсекает петлю, частные, канальные и служебные диапазоны.
func isBlocked(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 0:
			return true
		case v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127: // 100.64.0.0/10 (CGNAT)
			return true
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 0: // 192.0.0.0/24
			return true
		case v4[0] == 198 && (v4[1] == 18 || v4[1] == 19): // 198.18.0.0/15
			return true
		case v4[0] >= 240: // 240.0.0.0/4
			return true
		}
		return false
	}

	// GPT: IPv6-диапазоны, через которые можно дотянуться до локалхоста
	// или служебных адресов в обход обычной проверки.
	v6 := ip.To16()
	if v6 == nil {
		return true
	}
	switch {
	case v6[0] == 0xfe && v6[1]&0xc0 == 0xc0: // fec0::/10 site-local
		return true
	case v6[0] == 0x00 && v6[1] == 0x64 && v6[2] == 0xff && v6[3] == 0x9b: // 64:ff9b::/96 NAT64
		return true
	case v6[0] == 0x20 && v6[1] == 0x02: // 2002::/16 6to4
		return true
	case v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x00 && v6[3] == 0x00: // 2001::/32 Teredo
		return true
	case v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x0d && v6[3] == 0xb8: // 2001:db8::/32
		return true
	}
	return false
}

package agent

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

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

// Resolve проверяет порт, резолвит имя и возвращает уже проверенный IP.
// GPT: агент сам делает DNS и сам подключается по IP, а не по имени —
// так исключается DNS-rebinding, при котором домен сначала отдаёт
// публичный адрес, а на момент соединения — локальный.
func (g *Guard) Resolve(ctx context.Context, host string, port int) (string, error) {
	if !g.allowed(port) {
		return "", &protocol.OpenError{
			Code:    protocol.CodeNotAllowed,
			Message: fmt.Sprintf("порт %d запрещён настройками узла", port),
		}
	}
	if host == "" {
		return "", &protocol.OpenError{Code: protocol.CodeUnreachable, Message: "пустой адрес"}
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
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
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

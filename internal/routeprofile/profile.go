package routeprofile

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"exitnode/internal/client"
	"exitnode/internal/protocol"
)

const (
	Path       = "/etc/exitnode-route/route.env"
	KeyPath    = "/etc/exitnode-route/access-key"
	HelperPath = "/usr/local/lib/exitnode-route/select-domain"
	domainKey  = "EXITNODE_ROUTE_DOMAIN="
)

var hostname = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

type Settings struct {
	Domain string
	Owner  string
	Relay  string
}

type Invitation struct {
	Version int    `json:"version"`
	Server  string `json:"server"`
	Key     string `json:"key"`
}

type Selection struct {
	Invitation
	Domain string `json:"domain"`
}

func ValidDomain(name string) bool {
	return len(name) <= 253 && hostname.MatchString(name) && net.ParseIP(name) == nil
}

// GPT: Use the exact settings consumed by the installed route service.
func ReadSettings(path string) (Settings, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Settings{}, err
	}
	return parseSettings(raw)
}

func parseSettings(raw []byte) (Settings, error) {
	var out Settings
	seen := make(map[string]bool, 3)
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, _ := strings.Cut(strings.TrimSpace(line), "=")
		value = strings.TrimSpace(value)
		switch key {
		case "EXITNODE_ROUTE_DOMAIN":
			out.Domain = value
		case "EXITNODE_ROUTE_OWNER":
			out.Owner = value
		case "EXITNODE_ROUTE_RELAY":
			out.Relay = value
		default:
			continue
		}
		if seen[key] {
			return Settings{}, errors.New("duplicate route settings")
		}
		seen[key] = true
	}
	host, port, err := net.SplitHostPort(out.Relay)
	n, _ := strconv.Atoi(port)
	if !ValidDomain(out.Domain) || out.Owner == "" || len(out.Owner) > 128 ||
		err != nil || !ValidDomain(host) || n < 1 || n > 65535 {
		return Settings{}, errors.New("invalid route settings")
	}
	return out, nil
}

func (s Settings) Accepts(inv Invitation) bool {
	return inv.Version == 1 && inv.Server == s.Relay && inv.Key != "" && len(inv.Key) <= 255
}

// GPT: Limit the invitation to the installed relay and the authenticated owner's advertised sites.
func RequestPolicy(ctx context.Context, s Settings, inv Invitation) (protocol.Policy, error) {
	if !s.Accepts(inv) {
		return protocol.Policy{}, errors.New("invite_mismatch")
	}
	policy, err := client.QueryPolicy(ctx, inv.Server, inv.Key)
	if err != nil {
		return protocol.Policy{}, errors.New("policy_unavailable")
	}
	if policy.Owner != s.Owner {
		return protocol.Policy{}, errors.New("invite_mismatch")
	}
	domains := make([]string, 0, len(policy.Domains))
	for _, name := range policy.Domains {
		if ValidDomain(name) {
			domains = append(domains, name)
		}
	}
	policy.Domains = domains
	return policy, nil
}

// GPT: Accept exactly one bounded selection before comparing against the installed credential.
func DecodeSelection(input io.Reader) (Selection, error) {
	raw, err := io.ReadAll(io.LimitReader(input, 8193))
	if err != nil || len(raw) > 8192 {
		return Selection{}, errors.New("bad_request")
	}
	var sel Selection
	if json.Unmarshal(raw, &sel) != nil || !ValidDomain(sel.Domain) {
		return Selection{}, errors.New("bad_request")
	}
	return sel, nil
}

// GPT: The privileged helper changes one domain, with the existing relay and key left in place.
func Apply(ctx context.Context, input io.Reader) error {
	if os.Geteuid() != 0 {
		return errors.New("profile_failed")
	}
	sel, err := DecodeSelection(input)
	if err != nil {
		return err
	}
	original, err := os.ReadFile(Path)
	if err != nil {
		return errors.New("profile_failed")
	}
	settings, err := parseSettings(original)
	if err != nil {
		return errors.New("profile_failed")
	}
	key, err := os.ReadFile(KeyPath)
	if err != nil {
		return errors.New("profile_failed")
	}
	if !settings.Accepts(sel.Invitation) || subtle.ConstantTimeCompare([]byte(sel.Key), bytes.TrimSpace(key)) != 1 {
		return errors.New("invite_mismatch")
	}
	if err := routeOff(ctx); err != nil {
		return err
	}
	policy, err := RequestPolicy(ctx, settings, sel.Invitation)
	if err != nil {
		return err
	}
	if !allows(policy, sel.Domain) {
		return errors.New("domain_not_allowed")
	}
	if err := routeOff(ctx); err != nil {
		return err
	}
	if err := writeDomain(Path, original, sel.Domain); err != nil {
		return errors.New("profile_failed")
	}
	return nil
}

func allows(policy protocol.Policy, domain string) bool {
	for _, allowed := range policy.Domains {
		if domain == allowed {
			return true
		}
	}
	return false
}

func routeOff(ctx context.Context) error {
	raw, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "-p", "ActiveState",
		"--value", "--", "exitnode-route.service").Output()
	if err != nil || strings.TrimSpace(string(raw)) != "inactive" {
		return errors.New("stop_before_select")
	}
	return nil
}

func writeDomain(path string, current []byte, domain string) error {
	lines := strings.Split(string(current), "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), domainKey) {
			lines[i] = domainKey + domain
			break
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".route-env-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if _, err := tmp.WriteString(strings.Join(lines, "\n")); err != nil {
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

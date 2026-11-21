package clientui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"exitnode/internal/routeprofile"
)

const (
	routeUnit   = "exitnode-route.service"
	routeEngine = "exitnode-route-engine.service"
	routeClient = "exitnode-route-client.service"
	routeHeader = "X-Exitnode-Route-Token"
)

var routeFakeIP = netip.MustParsePrefix("198.19.255.248/29")

type systemRoute struct {
	origin, token string
	action        sync.Mutex
	mu            sync.Mutex
	probe         routeProbe
	invite        *routeprofile.Invitation
	policy        *invitePolicyView
}

type routeProbe struct {
	generation string
	result     string
	when       time.Time
}

type systemRouteView struct {
	Domain    string            `json:"domain"`
	Owner     string            `json:"owner"`
	State     string            `json:"state"`
	Enabled   bool              `json:"enabled"`
	Probe     string            `json:"probe,omitempty"`
	CheckedAt string            `json:"checked_at,omitempty"`
	Policy    *invitePolicyView `json:"policy,omitempty"`
}

type routeUnitState struct {
	load, active, invocation string
}

// GPT: Read only display settings from the root-owned system route configuration.
func openSystemRoute(origin string) (*systemRoute, error) {
	if runtime.GOOS != "linux" {
		return nil, nil
	}
	_, err := routeprofile.ReadSettings(routeprofile.Path)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	route := &systemRoute{origin: origin}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	route.token = hex.EncodeToString(token[:])
	return route, nil
}

// GPT: Open the panel from a private launcher so its token stays out of browser arguments.
func (route *systemRoute) launcher() (string, func(), error) {
	dir, err := os.MkdirTemp(os.Getenv("XDG_RUNTIME_DIR"), "exitnode-panel-")
	if err != nil {
		return "", nil, err
	}
	path := filepath.Join(dir, "client.html")
	cleanup := func() { _ = os.Remove(path); _ = os.Remove(dir) }
	body := fmt.Sprintf(`<!doctype html><meta charset="utf-8"><script>location.replace(%q)</script>`,
		route.origin+"/#exitnode-route="+route.token)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		cleanup()
		return "", nil, err
	}
	return (&url.URL{Scheme: "file", Path: path}).String(), cleanup, nil
}

func readRouteUnits(ctx context.Context) (map[string]routeUnitState, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "show",
		"--property=Id,LoadState,ActiveState,InvocationID", "--", routeUnit, routeEngine, routeClient).Output()
	if err != nil {
		return nil, err
	}
	units := make(map[string]routeUnitState, 3)
	for _, record := range strings.Split(strings.TrimSpace(string(output)), "\n\n") {
		var id string
		var status routeUnitState
		for _, line := range strings.Split(record, "\n") {
			field, value, _ := strings.Cut(line, "=")
			switch field {
			case "Id":
				id = value
			case "LoadState":
				status.load = value
			case "ActiveState":
				status.active = value
			case "InvocationID":
				status.invocation = value
			}
		}
		units[id] = status
	}
	return units, nil
}

func (route *systemRoute) status(ctx context.Context) (systemRouteView, string) {
	view := systemRouteView{State: "unknown"}
	settings, err := routeprofile.ReadSettings(routeprofile.Path)
	if err != nil {
		return view, ""
	}
	view.Domain, view.Owner = settings.Domain, settings.Owner
	route.mu.Lock()
	view.Policy = route.policy
	route.mu.Unlock()
	units, err := readRouteUnits(ctx)
	if err != nil || units[routeUnit].load != "loaded" {
		return view, ""
	}
	main, engine, client := units[routeUnit], units[routeEngine], units[routeClient]
	switch main.active {
	case "activating", "deactivating":
		view.State = "changing"
	case "inactive":
		view.State = "off"
	case "failed":
		view.State = "failed"
	case "active":
		view.Enabled, view.State = true, "blocked"
		if engine.active == "active" && client.active == "active" {
			view.State = "ready"
		}
	}
	if view.State != "ready" {
		return view, ""
	}
	generation := main.invocation + "/" + engine.invocation + "/" + client.invocation
	route.mu.Lock()
	probe := route.probe
	route.mu.Unlock()
	if probe.generation == generation {
		view.Probe, view.CheckedAt = probe.result, probe.when.Format(time.RFC3339)
	}
	return view, generation
}

// GPT: Check TLS through the dedicated resolver and the virtual TUN address only.
func (route *systemRoute) checkConnection(ctx context.Context, domain string) error {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	resolver := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, "172.31.252.2:53")
		},
	}
	ips, err := resolver.LookupNetIP(ctx, "ip4", domain+".")
	if err != nil || len(ips) != 1 || !routeFakeIP.Contains(ips[0]) {
		return errors.New("no virtual address for the selected domain")
	}
	path, err := exec.CommandContext(ctx, "/usr/sbin/ip", "-4", "route", "get", ips[0].String()).Output()
	if err != nil || !strings.Contains(" "+string(path)+" ", " dev exitnode-r2 ") {
		return errors.New("virtual address does not route to the TUN")
	}
	dialer := tls.Dialer{
		Config: &tls.Config{ServerName: domain, MinVersion: tls.VersionTLS12},
	}
	conn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(ips[0].String(), "443"))
	if err != nil {
		return err
	}
	return conn.Close()
}

func (route *systemRoute) serve(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get(routeHeader)), []byte(route.token)) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		view, _ := route.status(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(view)
		return
	}
	if !checkPost(w, r) {
		return
	}
	if r.Header.Get("Origin") != route.origin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var body struct {
		Action string
		Invite *routeprofile.Invitation
		Domain string
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&body); err != nil {
		http.Error(w, "bad_request", http.StatusBadRequest)
		return
	}
	if !route.action.TryLock() {
		http.Error(w, "busy", http.StatusConflict)
		return
	}
	defer route.action.Unlock()

	switch body.Action {
	case "start", "stop":
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		route.mu.Lock()
		route.probe = routeProbe{}
		route.mu.Unlock()
		if err := exec.CommandContext(ctx, "/usr/bin/systemctl", "--no-ask-password", body.Action, "--", routeUnit).Run(); err != nil {
			http.Error(w, "control_failed", http.StatusForbidden)
			return
		}
	case "invite":
		if code := route.inspectInvite(r.Context(), body.Invite); code != "" {
			http.Error(w, code, http.StatusBadRequest)
			return
		}
	case "select":
		if code := route.selectDomain(r.Context(), body.Domain); code != "" {
			http.Error(w, code, http.StatusBadRequest)
			return
		}
	case "probe":
		view, generation := route.status(r.Context())
		if view.State != "ready" {
			http.Error(w, "not_ready", http.StatusConflict)
			return
		}
		result := "ok"
		if err := route.checkConnection(r.Context(), view.Domain); err != nil {
			result = "failed"
		}
		route.mu.Lock()
		route.probe = routeProbe{generation: generation, result: result, when: time.Now()}
		route.mu.Unlock()
		route.refreshInvitationPolicy(r.Context())
	default:
		http.Error(w, "bad_request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

//go:embed route.js
var routeJS []byte

// GPT: Register the desktop route controls only when a private launcher is available.
func bindSystemRoute(mux *http.ServeMux, panelURL string, logger *log.Logger) (string, func()) {
	mux.HandleFunc("/system-route.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(routeJS)
	})
	route, err := openSystemRoute(strings.TrimSuffix(panelURL, "/"))
	if err != nil {
		logger.Printf("system route unavailable: %v", err)
	}
	if route == nil {
		return panelURL, func() {}
	}
	launcher, cleanup, err := route.launcher()
	if err != nil {
		logger.Printf("system route launcher unavailable: %v", err)
		return panelURL, func() {}
	}
	mux.HandleFunc("/api/system-route", route.serve)
	return launcher, cleanup
}

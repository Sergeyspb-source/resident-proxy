// Пакет ui — локальная панель агента. Слушает только loopback.
package ui

import (
	_ "embed"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"time"

	"exitnode/internal/monitor"
)

//go:embed index.html
var indexHTML []byte

// Info — состояние агента, которое панель показывает в шапке.
type Info struct {
	Name        string
	Relay       string
	Connected   bool
	Enabled     bool
	Since       time.Time
	MaxSessions int
}

// Controller — действия, доступные с панели.
type Controller interface {
	Info() Info
	SetEnabled(bool)
	KillAll()
}

type state struct {
	Name        string                    `json:"name"`
	Relay       string                    `json:"relay"`
	Connected   bool                      `json:"connected"`
	Enabled     bool                      `json:"enabled"`
	Uptime      int64                     `json:"uptime"`
	MaxSessions int                       `json:"max_sessions"`
	Sessions    []monitor.SessionSnapshot `json:"sessions"`
	InRate      float64                   `json:"in_rate"`
	OutRate     float64                   `json:"out_rate"`
	TotalIn     uint64                    `json:"total_in"`
	TotalOut    uint64                    `json:"total_out"`
	History     []float64                 `json:"history"`
	CPUProc     float64                   `json:"cpu_proc"`
	RSSMB       float64                   `json:"rss_mb"`
	CPUSys      float64                   `json:"cpu_sys"`
	MemSys      float64                   `json:"mem_sys"`
}

type handler struct {
	reg  *monitor.Registry
	sys  *monitor.System
	ctrl Controller
}

func Serve(addr string, reg *monitor.Registry, ctrl Controller, sys *monitor.System, logger *log.Logger, onReady func(url string)) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	if !isLoopback(addr) {
		logger.Printf("ВНИМАНИЕ: панель слушает не только localhost (%s)", addr)
	}

	h := &handler{reg: reg, sys: sys, ctrl: ctrl}
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.index)
	mux.HandleFunc("/api/state", h.getState)
	mux.HandleFunc("/api/toggle", h.toggle)
	mux.HandleFunc("/api/kill", h.kill)

	if onReady != nil {
		onReady("http://" + displayAddr(ln.Addr().String()) + "/")
	}

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return srv.Serve(ln)
}

func (h *handler) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(indexHTML)
}

func (h *handler) getState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	info := h.ctrl.Info()
	snap := h.reg.Snapshot()
	sys := h.sys.Snapshot()

	resp := state{
		Name:        info.Name,
		Relay:       info.Relay,
		Connected:   info.Connected,
		Enabled:     info.Enabled,
		Uptime:      int64(time.Since(info.Since).Seconds()),
		MaxSessions: info.MaxSessions,
		Sessions:    snap.Sessions,
		InRate:      snap.InRate,
		OutRate:     snap.OutRate,
		TotalIn:     snap.TotalIn,
		TotalOut:    snap.TotalOut,
		History:     snap.History,
		CPUProc:     sys.CPUProc,
		RSSMB:       sys.RSSMB,
		CPUSys:      sys.CPUSys,
		MemSys:      sys.MemSys,
	}
	if resp.Sessions == nil {
		resp.Sessions = []monitor.SessionSnapshot{}
	}
	if resp.History == nil {
		resp.History = []float64{}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

// toggle и kill требуют кастомный заголовок: сторонний сайт не сможет
// отправить такой запрос без CORS-preflight, который мы не разрешаем.
func (h *handler) toggle(w http.ResponseWriter, r *http.Request) {
	if !checkPost(w, r) {
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	h.ctrl.SetEnabled(body.Enabled)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (h *handler) kill(w http.ResponseWriter, r *http.Request) {
	if !checkPost(w, r) {
		return
	}
	h.ctrl.KillAll()
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func checkPost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if r.Header.Get("X-Requested-With") != "exitnode" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" || host == "localhost" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func displayAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "::" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

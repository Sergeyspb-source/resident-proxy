// Пакет ui — локальная панель агента. Слушает только loopback.
package ui

import (
	_ "embed"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
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

// LimitsView — ограничения узла и расход за сегодня и за месяц.
type LimitsView struct {
	QuotaMB         int64  `json:"quota_mb"`
	QuotaMonthMB    int64  `json:"quota_month_mb"`
	RateKBps        int64  `json:"rate_kbps"`
	Domains         string `json:"domains"`
	UsedBytes       int64  `json:"used_bytes"`
	QuotaBytes      int64  `json:"quota_bytes"`
	UsedMonthBytes  int64  `json:"used_month_bytes"`
	QuotaMonthBytes int64  `json:"quota_month_bytes"`
}

// KeyView — ключ доступа, который владелец узла передаёт коллеге.
type KeyView struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Value string `json:"value"`
}

// Controller — действия, доступные с панели.
type Controller interface {
	Info() Info
	SetEnabled(bool)
	KillAll()
	Limits() LimitsView
	SetLimits(LimitsView) error
	Keys() []KeyView
	AddKey(string) (KeyView, error)
	RemoveKey(string) error
	KeyValue(string) (string, error)
	Autostart() bool
	SetAutostart(bool) error
}

type state struct {
	Name        string                    `json:"name"`
	Relay       string                    `json:"relay"`
	Connected   bool                      `json:"connected"`
	Enabled     bool                      `json:"enabled"`
	Uptime      int64                     `json:"uptime"`
	MaxSessions int                       `json:"max_sessions"`
	Limits      LimitsView                `json:"limits"`
	Quota       bool                      `json:"quota_exceeded"`
	Keys        []KeyView                 `json:"keys"`
	Autostart   bool                      `json:"autostart"`
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
	if !isLoopback(addr) {
		return errors.New("панель должна слушать только 127.0.0.1; удалённый доступ запрещён")
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	h := &handler{reg: reg, sys: sys, ctrl: ctrl}
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.index)
	mux.HandleFunc("/api/state", h.getState)
	mux.HandleFunc("/api/toggle", h.toggle)
	mux.HandleFunc("/api/kill", h.kill)
	mux.HandleFunc("/api/limits", h.setLimits)
	mux.HandleFunc("/api/keys/add", h.addKey)
	mux.HandleFunc("/api/keys/remove", h.removeKey)
	mux.HandleFunc("/api/keys/reveal", h.revealKey)
	mux.HandleFunc("/api/autostart", h.setAutostart)

	// GPT: проверка Host и RemoteAddr закрывает DNS-rebinding на панель.
	// Без неё страница evil.com могла переехать на 127.0.0.1 и прочитать ключи.
	guard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validRequest(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
		mux.ServeHTTP(w, r)
	})

	if onReady != nil {
		onReady("http://" + displayAddr(ln.Addr().String()) + "/")
	}

	srv := &http.Server{
		Handler:           guard,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	return srv.Serve(ln)
}

func validRequest(r *http.Request) bool {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return false
	}

	remote, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(remote)
	return ip != nil && ip.IsLoopback()
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
	lim := h.ctrl.Limits()
	quotaHit := (lim.QuotaBytes > 0 && lim.UsedBytes >= lim.QuotaBytes) ||
		(lim.QuotaMonthBytes > 0 && lim.UsedMonthBytes >= lim.QuotaMonthBytes)

	resp := state{
		Name:        info.Name,
		Relay:       info.Relay,
		Connected:   info.Connected,
		Enabled:     info.Enabled,
		Uptime:      int64(time.Since(info.Since).Seconds()),
		MaxSessions: info.MaxSessions,
		Limits:      lim,
		Quota:       quotaHit,
		Keys:        h.ctrl.Keys(),
		Autostart:   h.ctrl.Autostart(),
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

func (h *handler) setLimits(w http.ResponseWriter, r *http.Request) {
	if !checkPost(w, r) {
		return
	}
	var body LimitsView
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.ctrl.SetLimits(body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (h *handler) addKey(w http.ResponseWriter, r *http.Request) {
	if !checkPost(w, r) {
		return
	}
	var body struct {
		Label string `json:"label"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	key, err := h.ctrl.AddKey(body.Label)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "key": key})
}

func (h *handler) removeKey(w http.ResponseWriter, r *http.Request) {
	if !checkPost(w, r) {
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.ctrl.RemoveKey(body.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (h *handler) setAutostart(w http.ResponseWriter, r *http.Request) {
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
	if err := h.ctrl.SetAutostart(body.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (h *handler) revealKey(w http.ResponseWriter, r *http.Request) {
	if !checkPost(w, r) {
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	value, err := h.ctrl.KeyValue(body.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "value": value})
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
	if host == "localhost" {
		return true
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

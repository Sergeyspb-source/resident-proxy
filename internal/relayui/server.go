// Пакет relayui — локальная панель шлюза: узлы, сессии, скорость.
// GPT: добавлено, чтобы состояние шлюза было видно, а не только в журнале.
package relayui

import (
	_ "embed"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"exitnode/internal/relay"
)

//go:embed index.html
var indexHTML []byte

type handler struct {
	r  *relay.Relay
	mu sync.Mutex
	// последний замер для скорости
	lastT   time.Time
	lastIn  uint64
	lastOut uint64
}

func Serve(addr string, r *relay.Relay, logger *log.Logger, onReady func(url string)) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return errors.New("панель шлюза должна слушать только 127.0.0.1")
		}
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	h := &handler{r: r}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(indexHTML)
	})
	mux.HandleFunc("/api/state", h.getState)

	guard := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !validRequest(req) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
		mux.ServeHTTP(w, req)
	})

	if onReady != nil {
		onReady("http://" + ln.Addr().String() + "/")
	}
	srv := &http.Server{
		Handler:           guard,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	logger.Printf("панель шлюза: %s", ln.Addr())
	return srv.Serve(ln)
}

type agentView struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Remote   string `json:"remote"`
	Since    int64  `json:"since"`
	Keys     int    `json:"keys"`
	Sessions int64  `json:"sessions"`
	In       uint64 `json:"in"`
	Out      uint64 `json:"out"`
}

type sessionView struct {
	ID     uint64 `json:"id"`
	Agent  string `json:"agent"`
	Client string `json:"client"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Since  int64  `json:"since"`
	In     uint64 `json:"in"`
	Out    uint64 `json:"out"`
}

func (h *handler) getState(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	agents, sessions, totalIn, totalOut := h.r.Snapshot()

	now := time.Now()
	h.mu.Lock()
	inRate, outRate := 0.0, 0.0
	if !h.lastT.IsZero() {
		dt := now.Sub(h.lastT).Seconds()
		if dt > 0.2 {
			inRate = float64(totalIn-h.lastIn) / dt
			outRate = float64(totalOut-h.lastOut) / dt
		}
	}
	h.lastT, h.lastIn, h.lastOut = now, totalIn, totalOut
	h.mu.Unlock()

	resp := struct {
		Agents   []agentView   `json:"agents"`
		Sessions []sessionView `json:"sessions"`
		TotalIn  uint64        `json:"total_in"`
		TotalOut uint64        `json:"total_out"`
		InRate   float64       `json:"in_rate"`
		OutRate  float64       `json:"out_rate"`
	}{
		Agents:   make([]agentView, 0, len(agents)),
		Sessions: make([]sessionView, 0, len(sessions)),
		TotalIn:  totalIn,
		TotalOut: totalOut,
		InRate:   inRate,
		OutRate:  outRate,
	}
	for _, a := range agents {
		resp.Agents = append(resp.Agents, agentView{
			Name: a.Name, Version: a.Version, Remote: a.Remote,
			Since: a.Since.Unix(), Keys: a.Keys, Sessions: a.Sessions,
			In: a.In, Out: a.Out,
		})
	}
	for _, s := range sessions {
		resp.Sessions = append(resp.Sessions, sessionView{
			ID: s.ID, Agent: s.Agent, Client: s.Client, Host: s.Host, Port: s.Port,
			Since: s.Since.Unix(), In: s.In, Out: s.Out,
		})
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
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

// Пакет clientui — локальное окно клиента: ключ, статус, подключение.
package clientui

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"exitnode/internal/buildinfo"
	"exitnode/internal/client"
	"exitnode/internal/sysproxy"
)

//go:embed index.html
var indexHTML []byte

type saved struct {
	Server string `json:"server"`
	Key    string `json:"key"`
}

type App struct {
	mgr  *client.Manager
	log  *log.Logger
	path string

	mu   sync.Mutex
	cfg  saved
	last string
}

func NewApp(mgr *client.Manager, path string, logger *log.Logger) *App {
	a := &App{mgr: mgr, path: path, log: logger}
	a.load()
	// GPT: если прошлый запуск завершился аварийно, возвращаем настройки прокси.
	sysproxy.RestoreIfLeftover()
	return a
}

func (a *App) load() {
	if a.path == "" {
		return
	}
	b, err := os.ReadFile(a.path)
	if err != nil {
		return
	}
	var s saved
	if json.Unmarshal(b, &s) == nil {
		a.mu.Lock()
		a.cfg = s
		a.mu.Unlock()
	}
}

func (a *App) save() {
	if a.path == "" {
		return
	}
	a.mu.Lock()
	s := a.cfg
	a.mu.Unlock()
	b, _ := json.MarshalIndent(s, "", "  ")
	_ = os.MkdirAll(filepath.Dir(a.path), 0o700)
	_ = os.WriteFile(a.path, b, 0o600)
}

// Connect подключает клиент. Пустые поля берутся из сохранённого приглашения.
func (a *App) Connect(server, key string) error {
	server = strings.TrimSpace(server)
	key = strings.TrimSpace(key)

	a.mu.Lock()
	if server == "" {
		server = a.cfg.Server
	}
	if key == "" {
		key = a.cfg.Key
	}
	a.mu.Unlock()

	if server == "" || key == "" {
		return errors.New("нужны адрес шлюза и ключ")
	}

	listen, err := freeListen()
	if err != nil {
		a.setError(err.Error())
		return err
	}
	cfg := client.Config{
		Listen: listen,
		Server: server,
		Key:    key,
		TLS:    true,
	}
	if err := a.mgr.Start(cfg); err != nil {
		a.setError(err.Error())
		return err
	}

	a.mu.Lock()
	a.cfg = saved{Server: server, Key: key}
	a.last = ""
	a.mu.Unlock()
	a.save()
	return nil
}

func (a *App) Disconnect() {
	_ = sysproxy.Disable()
	a.mgr.Stop()
}

// SetSystemProxy включает или выключает системный прокси Windows.
// GPT: прокси включается только при работающем клиенте, иначе порт мёртв.
func (a *App) SetSystemProxy(on bool) error {
	if !sysproxy.Supported() {
		return errors.New("системный прокси доступен только в Windows")
	}
	if !on {
		return sysproxy.Disable()
	}
	st := a.mgr.State()
	if !st.Running || st.HTTPListen == "" {
		return errors.New("сначала подключитесь")
	}
	return sysproxy.Enable(st.HTTPListen)
}

func (a *App) Toggle() {
	if a.mgr.Running() {
		a.Disconnect()
		return
	}
	_ = a.Connect("", "")
}

func (a *App) Running() bool { return a.mgr.Running() }

// Import читает файл приглашения и сразу подключается.
func (a *App) Import(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var inv struct {
		Version int    `json:"version"`
		Server  string `json:"server"`
		Key     string `json:"key"`
		Name    string `json:"name"`
	}
	if err := json.Unmarshal(b, &inv); err != nil {
		return errors.New("файл не похож на приглашение")
	}
	if inv.Server == "" || inv.Key == "" {
		return errors.New("в приглашении нет адреса или ключа")
	}

	a.mu.Lock()
	a.cfg = saved{Server: inv.Server, Key: inv.Key}
	a.mu.Unlock()
	a.save()
	return a.Connect("", "")
}

func (a *App) setError(msg string) {
	a.mu.Lock()
	a.last = msg
	a.mu.Unlock()
}

// freeListen ищет свободный локальный порт, начиная с 1080.
// GPT: Xray и другие клиенты часто занимают 1080, поэтому не падаем,
// а берём следующий свободный и показываем его в окне.
func freeListen() (string, error) {
	for p := 1080; p <= 1099; p++ {
		addr := fmt.Sprintf("127.0.0.1:%d", p)
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			_ = ln.Close()
			return addr, nil
		}
	}
	return "", errors.New("нет свободного порта в диапазоне 1080–1099")
}

type stateView struct {
	Version        string `json:"version"`
	Running        bool   `json:"running"`
	Listen         string `json:"listen"`
	Server         string `json:"server"`
	HasKey         bool   `json:"has_key"`
	In             uint64 `json:"in"`
	Out            uint64 `json:"out"`
	Uptime         int64  `json:"uptime"`
	Platform       string `json:"platform"`
	SystemProxy    bool   `json:"system_proxy"`
	CanSystemProxy bool   `json:"can_system_proxy"`
	HTTPProxy      string `json:"http_proxy"`
	Error          string `json:"error,omitempty"`
}

func (a *App) state() stateView {
	st := a.mgr.State()
	a.mu.Lock()
	hasKey := a.cfg.Key != ""
	last := a.last
	a.mu.Unlock()
	return stateView{
		Version:        buildinfo.Version,
		Running:        st.Running,
		Listen:         st.Listen,
		Server:         st.Server,
		HasKey:         hasKey,
		In:             st.In,
		Out:            st.Out,
		Uptime:         int64(time.Since(st.Started).Seconds()),
		Platform:       runtime.GOOS,
		SystemProxy:    sysproxy.Enabled(),
		CanSystemProxy: sysproxy.Supported(),
		HTTPProxy:      st.HTTPListen,
		Error:          last,
	}
}

// GPT: Serve the optional system route API behind a private desktop launcher.
func Serve(addr string, app *App, logger *log.Logger, onReady func(url string)) error {
	if !isLoopback(addr) {
		return errors.New("окно клиента должно слушать только 127.0.0.1")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(indexHTML)
	})
	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(app.state())
	})
	mux.HandleFunc("/api/connect", func(w http.ResponseWriter, r *http.Request) {
		if !checkPost(w, r) {
			return
		}
		var body struct {
			Server string `json:"server"`
			Key    string `json:"key"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := app.Connect(body.Server, body.Key); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/api/disconnect", func(w http.ResponseWriter, r *http.Request) {
		if !checkPost(w, r) {
			return
		}
		app.Disconnect()
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	// GPT: системный прокси Windows включается и выключается из панели клиента.
	mux.HandleFunc("/api/system-proxy", func(w http.ResponseWriter, r *http.Request) {
		if !checkPost(w, r) {
			return
		}
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := app.SetSystemProxy(body.Enabled); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	guard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validRequest(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
		mux.ServeHTTP(w, r)
	})

	panelURL, cleanup := bindSystemRoute(mux, "http://"+displayAddr(ln.Addr().String())+"/", logger)
	defer cleanup()
	if onReady != nil {
		onReady(panelURL)
	}
	srv := &http.Server{
		Handler:           guard,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	logger.Printf("окно клиента: %s", ln.Addr())
	return srv.Serve(ln)
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

// Пакет client — локальный SOCKS5 для коллеги.
// Браузер не умеет передавать пароль в SOCKS5, поэтому клиент сам
// добавляет ключ при подключении к шлюзу.
package client

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"exitnode/internal/protocol"
	"exitnode/internal/secure"
)

type Config struct {
	Listen      string
	HTTPListen  string
	Server      string
	Key         string
	User        string
	TLS         bool
	ServerName  string
	Insecure    bool
	AllowRemote bool
}

type State struct {
	Running    bool
	Listen     string
	HTTPListen string
	Server     string
	Started    time.Time
	In         uint64
	Out        uint64
}

// Manager позволяет включать и выключать локальный прокси без перезапуска.
type Manager struct {
	log *log.Logger

	mu      sync.Mutex
	cfg     Config
	ln      net.Listener
	hln     net.Listener
	conns   map[net.Conn]struct{}
	started time.Time
	in      atomic.Uint64
	out     atomic.Uint64
}

func NewManager(logger *log.Logger) *Manager {
	return &Manager{log: logger}
}

func (m *Manager) Start(cfg Config) error {
	if !cfg.AllowRemote {
		host, _, err := net.SplitHostPort(cfg.Listen)
		ip := net.ParseIP(host)
		if err != nil || (host != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return errors.New("локальный SOCKS5 должен слушать 127.0.0.1; для LAN добавьте -allow-remote")
		}
	}
	if !cfg.TLS {
		m.log.Printf("ВНИМАНИЕ: ключ передаётся без TLS (только для локальной сети)")
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}

	// GPT: второй слушатель — HTTP-прокси для системных настроек Windows:
	// WinINET не умеет SOCKS5, а HTTP CONNECT умеет.
	if cfg.HTTPListen == "" {
		addr, err := freeHTTPListen()
		if err != nil {
			ln.Close()
			return err
		}
		cfg.HTTPListen = addr
	}
	hln, err := net.Listen("tcp", cfg.HTTPListen)
	if err != nil {
		ln.Close()
		return err
	}

	m.mu.Lock()
	if m.ln != nil {
		m.mu.Unlock()
		ln.Close()
		hln.Close()
		return errors.New("клиент уже подключён")
	}
	m.cfg = cfg
	m.ln = ln
	m.hln = hln
	m.conns = make(map[net.Conn]struct{})
	m.started = time.Now()
	m.in.Store(0)
	m.out.Store(0)
	m.mu.Unlock()

	m.log.Printf("локальный SOCKS5 на %s, шлюз %s", cfg.Listen, cfg.Server)
	m.log.Printf("HTTP-прокси для системы на %s", cfg.HTTPListen)
	go m.acceptLoop(ln)
	go m.acceptHTTP(hln)
	return nil
}

// freeHTTPListen ищет свободный порт для HTTP-прокси.
func freeHTTPListen() (string, error) {
	for p := 8080; p <= 8099; p++ {
		addr := fmt.Sprintf("127.0.0.1:%d", p)
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			_ = ln.Close()
			return addr, nil
		}
	}
	return "", errors.New("нет свободного порта в диапазоне 8080–8099")
}

func (m *Manager) Stop() {
	m.mu.Lock()
	ln := m.ln
	hln := m.hln
	m.ln = nil
	m.hln = nil
	conns := make([]net.Conn, 0, len(m.conns))
	for c := range m.conns {
		conns = append(conns, c)
	}
	m.conns = nil
	m.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	if hln != nil {
		_ = hln.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
	if ln != nil {
		m.log.Printf("клиент отключён")
	}
}

func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ln != nil
}

func (m *Manager) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := State{
		Running:    m.ln != nil,
		Listen:     m.cfg.Listen,
		HTTPListen: m.cfg.HTTPListen,
		Server:     m.cfg.Server,
		Started:    m.started,
		In:         m.in.Load(),
		Out:        m.out.Load(),
	}
	return st
}

func (m *Manager) acceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go m.handle(c)
	}
}

// acceptHTTP принимает подключения HTTP-прокси.
func (m *Manager) acceptHTTP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go m.handleHTTP(c)
	}
}

// dialTarget открывает шифрованный туннель до цели на узле выхода.
func (m *Manager) dialTarget(cfg Config, host string, port int) (net.Conn, error) {
	up, err := dialUpstream(cfg)
	if err != nil {
		return nil, err
	}
	sec, err := secure.NewConn(up, secure.DeriveKey(cfg.Key))
	if err != nil {
		up.Close()
		return nil, err
	}
	if err := protocol.WriteJSON(sec, protocol.E2EConnect{Host: host, Port: port}); err != nil {
		sec.Close()
		return nil, err
	}
	return &countConn{
		Conn:    sec,
		onRead:  func(n int) { m.out.Add(uint64(n)) },
		onWrite: func(n int) { m.in.Add(uint64(n)) },
	}, nil
}

// handleHTTP обслуживает HTTP-прокси: CONNECT для HTTPS и обычные запросы.
func (m *Manager) handleHTTP(c net.Conn) {
	defer c.Close()
	if !m.track(c) {
		return
	}
	defer m.untrack(c)

	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	defer req.Body.Close()

	host, port := req.Host, 80
	if req.Method == http.MethodConnect {
		port = 443
		if h, p, err := net.SplitHostPort(req.Host); err == nil {
			host = h
			if n, err := strconv.Atoi(p); err == nil {
				port = n
			}
		}
	} else if req.URL != nil && req.URL.Host != "" {
		host = req.URL.Hostname()
		if p := req.URL.Port(); p != "" {
			if n, err := strconv.Atoi(p); err == nil {
				port = n
			}
		}
	}
	if host == "" {
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	up, err := m.dialTarget(m.cfgCopy(), host, port)
	if err != nil {
		m.log.Printf("%s:%d: %v", host, port, err)
		_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer up.Close()

	if req.Method == http.MethodConnect {
		if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}
		_ = c.SetDeadline(time.Time{})
		protocol.Join(&protocol.BufConn{Conn: c, R: br}, up)
		return
	}

	req.RequestURI = ""
	req.URL.Scheme = "http"
	req.URL.Host = host
	req.Header.Del("Proxy-Connection")
	req.Header.Set("Connection", "close")
	if err := req.Write(up); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	protocol.Join(c, up)
}

func (m *Manager) track(c net.Conn) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ln == nil {
		return false
	}
	m.conns[c] = struct{}{}
	return true
}

func (m *Manager) untrack(c net.Conn) {
	m.mu.Lock()
	if m.conns != nil {
		delete(m.conns, c)
	}
	m.mu.Unlock()
}

func (m *Manager) cfgCopy() Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg
}

func (m *Manager) handle(c net.Conn) {
	defer c.Close()
	if !m.track(c) {
		return
	}
	defer m.untrack(c)

	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)

	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil {
		return
	}
	if head[0] != 5 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return
	}
	if req[0] != 5 || req[1] != 1 {
		reply(c, 7)
		return
	}
	host, err := readAddr(br, req[3])
	if err != nil {
		reply(c, 8)
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(br, portBuf); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(portBuf))

	cfg := m.cfgCopy()
	sec, err := m.dialTarget(cfg, host, port)
	if err != nil {
		m.log.Printf("%s:%d: %v", host, port, err)
		reply(c, 5)
		return
	}

	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		sec.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	protocol.Join(&protocol.BufConn{Conn: c, R: br}, sec)
}

// countConn считает байты в обе стороны для статистики клиента.
type countConn struct {
	net.Conn
	onRead  func(int)
	onWrite func(int)
}

func (c *countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.onRead(n)
	}
	return n, err
}

func (c *countConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.onWrite(n)
	}
	return n, err
}

// Run — консольный режим: подключиться и работать до остановки процесса.
func Run(cfg Config, logger *log.Logger) error {
	m := NewManager(logger)
	if err := m.Start(cfg); err != nil {
		return err
	}
	select {}
}

// dialUpstream проходит SOCKS5-рукопожатие со шлюзом. Вместо пароля
// отправляется sha256 ключа, а целью указывается фиктивный адрес:
// шлюз не должен знать ни ключ, ни настоящий сайт.
func dialUpstream(cfg Config) (net.Conn, error) {
	if len(cfg.Key) > 255 {
		return nil, errors.New("ключ слишком длинный")
	}
	pass := keyHash(cfg.Key)
	if len(pass) > 255 {
		return nil, errors.New("ключ слишком длинный")
	}

	d := net.Dialer{Timeout: 15 * time.Second}
	var c net.Conn
	var err error
	if cfg.TLS {
		serverName := cfg.ServerName
		if serverName == "" {
			host, _, splitErr := net.SplitHostPort(cfg.Server)
			if splitErr != nil {
				return nil, splitErr
			}
			serverName = host
		}
		c, err = tls.DialWithDialer(&d, "tcp", cfg.Server, &tls.Config{
			MinVersion:         tls.VersionTLS13,
			ServerName:         serverName,
			InsecureSkipVerify: cfg.Insecure,
		})
	} else {
		c, err = d.Dial("tcp", cfg.Server)
	}
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()

	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := c.Write([]byte{5, 1, 2}); err != nil {
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	if resp[0] != 5 || resp[1] != 2 {
		return nil, errors.New("шлюз не запросил ключ")
	}

	user := cfg.User
	if user == "" {
		user = "key"
	}
	if len(user) > 255 {
		user = user[:255]
	}
	auth := []byte{1, byte(len(user))}
	auth = append(auth, user...)
	auth = append(auth, byte(len(pass)))
	auth = append(auth, pass...)
	if _, err := c.Write(auth); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	if resp[0] != 1 || resp[1] != 0 {
		return nil, errors.New("ключ отклонён шлюзом")
	}

	h := protocol.E2EHost
	req := []byte{5, 1, 0, 3, byte(len(h))}
	req = append(req, h...)
	req = append(req, 0x01, 0xBB) // 443
	if _, err := c.Write(req); err != nil {
		return nil, err
	}

	respHead := make([]byte, 4)
	if _, err := io.ReadFull(c, respHead); err != nil {
		return nil, err
	}
	if respHead[0] != 5 || respHead[1] != 0 {
		return nil, fmt.Errorf("шлюз ответил кодом %d", respHead[1])
	}
	switch respHead[3] {
	case 1:
		if _, err := io.ReadFull(c, make([]byte, 4+2)); err != nil {
			return nil, err
		}
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(c, make([]byte, int(l[0])+2)); err != nil {
			return nil, err
		}
	case 4:
		if _, err := io.ReadFull(c, make([]byte, 16+2)); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("неизвестный ответ шлюза")
	}

	_ = c.SetDeadline(time.Time{})
	ok = true
	return c, nil
}

func keyHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func readAddr(br *bufio.Reader, atyp byte) (string, error) {
	switch atyp {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return "", err
		}
		if l[0] == 0 {
			return "", errors.New("пустой домен")
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(br, b); err != nil {
			return "", err
		}
		return string(b), nil
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	}
	return "", errors.New("неизвестный тип адреса")
}

func reply(c net.Conn, code byte) {
	_, _ = c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
}

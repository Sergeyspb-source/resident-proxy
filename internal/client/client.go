// Пакет client — локальный SOCKS5 для коллеги.
// Браузер не умеет передавать пароль в SOCKS5, поэтому клиент сам
// добавляет ключ при подключении к шлюзу.
package client

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"exitnode/internal/protocol"
)

type Config struct {
	Listen      string
	Server      string
	Key         string
	User        string
	TLS         bool
	ServerName  string
	Insecure    bool
	AllowRemote bool
}

type State struct {
	Running bool
	Listen  string
	Server  string
	Started time.Time
	In      uint64
	Out     uint64
}

// Manager позволяет включать и выключать локальный прокси без перезапуска.
type Manager struct {
	log *log.Logger

	mu      sync.Mutex
	cfg     Config
	ln      net.Listener
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

	m.mu.Lock()
	if m.ln != nil {
		m.mu.Unlock()
		ln.Close()
		return errors.New("клиент уже подключён")
	}
	m.cfg = cfg
	m.ln = ln
	m.conns = make(map[net.Conn]struct{})
	m.started = time.Now()
	m.in.Store(0)
	m.out.Store(0)
	m.mu.Unlock()

	m.log.Printf("локальный SOCKS5 на %s, шлюз %s", cfg.Listen, cfg.Server)
	go m.acceptLoop(ln)
	return nil
}

func (m *Manager) Stop() {
	m.mu.Lock()
	ln := m.ln
	m.ln = nil
	conns := make([]net.Conn, 0, len(m.conns))
	for c := range m.conns {
		conns = append(conns, c)
	}
	m.conns = nil
	m.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
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
		Running: m.ln != nil,
		Listen:  m.cfg.Listen,
		Server:  m.cfg.Server,
		Started: m.started,
		In:      m.in.Load(),
		Out:     m.out.Load(),
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
	up, err := dialUpstream(cfg, host, port)
	if err != nil {
		m.log.Printf("%s:%d: %v", host, port, err)
		reply(c, 5)
		return
	}
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		up.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})

	metered := &countConn{
		Conn: up,
		onRead: func(n int) {
			m.out.Add(uint64(n))
		},
		onWrite: func(n int) {
			m.in.Add(uint64(n))
		},
	}
	protocol.Join(&protocol.BufConn{Conn: c, R: br}, metered)
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

// dialUpstream проходит SOCKS5-рукопожатие со шлюзом, передавая ключ как пароль.
func dialUpstream(cfg Config, host string, port int) (net.Conn, error) {
	if len(cfg.Key) > 255 {
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
	auth = append(auth, byte(len(cfg.Key)))
	auth = append(auth, cfg.Key...)
	if _, err := c.Write(auth); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	if resp[0] != 1 || resp[1] != 0 {
		return nil, errors.New("ключ отклонён шлюзом")
	}

	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 1)
			req = append(req, v4...)
		} else {
			req = append(req, 4)
			req = append(req, ip...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("слишком длинное имя")
		}
		req = append(req, 3, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
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

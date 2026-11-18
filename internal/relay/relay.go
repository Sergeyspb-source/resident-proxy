// Пакет relay — шлюз на VPS2: принимает агентов и обслуживает SOCKS5.
package relay

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"exitnode/internal/protocol"
)

type Config struct {
	SocksAddr  string
	TunnelAddr string
	CertFile   string
	KeyFile    string
	Token      string
	SocksTLS   bool
	Dev        bool
}

type agentLink struct {
	name    string
	version string
	remote  string
	since   time.Time
	keys    []protocol.Key
	closed  bool
	sess    *yamux.Session
}

type Relay struct {
	cfg Config
	log *log.Logger

	mu    sync.Mutex
	links []*agentLink
	byKey map[string]*agentLink

	tunnelSem chan struct{}
	socksSem  chan struct{}
}

const (
	maxTunnelConns = 64
	maxSocksConns  = 256
)

func New(cfg Config, logger *log.Logger) *Relay {
	return &Relay{
		cfg:       cfg,
		log:       logger,
		byKey:     make(map[string]*agentLink),
		tunnelSem: make(chan struct{}, maxTunnelConns),
		socksSem:  make(chan struct{}, maxSocksConns),
	}
}

func (r *Relay) Serve() error {
	tln, err := r.listenTunnel()
	if err != nil {
		return fmt.Errorf("туннель: %w", err)
	}
	defer tln.Close()

	go func() {
		for {
			c, err := tln.Accept()
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					time.Sleep(300 * time.Millisecond)
					continue
				}
				return
			}
			go r.handleTunnel(c)
		}
	}()
	r.log.Printf("приём агентов на %s", r.cfg.TunnelAddr)

	sln, err := r.listenSocks()
	if err != nil {
		return fmt.Errorf("socks: %w", err)
	}
	defer sln.Close()
	r.log.Printf("SOCKS5 на %s (TLS: %v)", r.cfg.SocksAddr, r.cfg.SocksTLS)

	return r.serveSocks(sln)
}

func (r *Relay) certPair() (tls.Certificate, error) {
	return tls.LoadX509KeyPair(r.cfg.CertFile, r.cfg.KeyFile)
}

func (r *Relay) listenTunnel() (net.Listener, error) {
	if r.cfg.CertFile == "" {
		if !r.cfg.Dev {
			return nil, errors.New("без сертификата туннель не шифруется; для теста добавьте -dev")
		}
		return net.Listen("tcp", r.cfg.TunnelAddr)
	}
	cert, err := r.certPair()
	if err != nil {
		return nil, err
	}
	return tls.Listen("tcp", r.cfg.TunnelAddr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
}

// listenSocks по умолчанию требует TLS: ключ передаётся как пароль SOCKS5
// и не должен идти открытым текстом через VPS1.
func (r *Relay) listenSocks() (net.Listener, error) {
	if !r.cfg.SocksTLS {
		if !r.cfg.Dev {
			return nil, errors.New("SOCKS5 без TLS передаёт ключи открытым текстом; для теста добавьте -dev")
		}
		return net.Listen("tcp", r.cfg.SocksAddr)
	}
	if r.cfg.CertFile == "" {
		return nil, errors.New("для -socks-tls нужны -cert и -key")
	}
	cert, err := r.certPair()
	if err != nil {
		return nil, err
	}
	return tls.Listen("tcp", r.cfg.SocksAddr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
}

func (r *Relay) tokenOK(got string) bool {
	a := sha256.Sum256([]byte(got))
	b := sha256.Sum256([]byte(r.cfg.Token))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// handleTunnel принимает агента: проверяет токен, поднимает yamux
// и держит соединение, пока агент не отключится.
func (r *Relay) handleTunnel(c net.Conn) {
	select {
	case r.tunnelSem <- struct{}{}:
		defer func() { <-r.tunnelSem }()
	default:
		_ = c.Close()
		return
	}

	remote := c.RemoteAddr().String()
	defer c.Close()

	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	bc := protocol.NewBufConn(c)

	var hello protocol.Hello
	if err := protocol.ReadJSON(bc.R, &hello); err != nil {
		r.log.Printf("агент %s: нет приветствия: %v", remote, err)
		return
	}
	if !r.tokenOK(hello.Token) {
		_ = protocol.WriteJSON(c, protocol.Ack{Error: "неверный токен"})
		r.log.Printf("агент %s: неверный токен", remote)
		return
	}
	if err := protocol.WriteJSON(c, protocol.Ack{OK: true}); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})

	sess, err := yamux.Server(bc, protocol.MuxConfig())
	if err != nil {
		r.log.Printf("агент %s: yamux: %v", remote, err)
		return
	}

	name := cleanName(hello.Name)
	link := &agentLink{
		name:    name,
		version: cleanName(hello.Version),
		remote:  remote,
		since:   time.Now(),
		keys:    hello.Keys,
		sess:    sess,
	}
	r.addLink(link)
	r.log.Printf("агент %q подключён: %s, версия %q, ключей: %d", name, remote, link.version, len(hello.Keys))
	defer func() {
		r.removeLink(link)
		r.log.Printf("агент %q отключён (%s)", name, remote)
	}()

	// Агент может присылать служебные сообщения (обновление ключей),
	// не разрывая туннель.
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go r.handleAgentControl(link, st)
	}
}

func cleanName(s string) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > 64 {
		s = string(r[:64])
	}
	return s
}

func (r *Relay) handleAgentControl(link *agentLink, st *yamux.Stream) {
	defer st.Close()
	_ = st.SetReadDeadline(time.Now().Add(10 * time.Second))
	bc := protocol.NewBufConn(st)

	var msg protocol.Control
	if err := protocol.ReadJSON(bc.R, &msg); err != nil {
		return
	}
	if msg.Type == protocol.ControlKeys {
		r.setLinkKeys(link, msg.Keys)
	}
}

func (r *Relay) addLink(l *agentLink) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.links = append(r.links, l)
	l.keys = r.indexKeysLocked(l, l.keys)
}

// indexKeysLocked принимает только те хеши, которые ещё не выданы другому
// живому узлу: иначе агент с токеном мог бы перехватить чужой ключ.
func (r *Relay) indexKeysLocked(l *agentLink, keys []protocol.Key) []protocol.Key {
	accepted := make([]protocol.Key, 0, len(keys))
	for _, k := range keys {
		if k.Hash == "" {
			continue
		}
		if owner, ok := r.byKey[k.Hash]; ok && owner != l && !owner.closed {
			r.log.Printf("конфликт ключей: узел %q попытался занять ключ узла %q", l.name, owner.name)
			continue
		}
		r.byKey[k.Hash] = l
		accepted = append(accepted, k)
	}
	return accepted
}

func (r *Relay) setLinkKeys(l *agentLink, keys []protocol.Key) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if l.closed {
		return
	}
	for hash, owner := range r.byKey {
		if owner == l {
			delete(r.byKey, hash)
		}
	}
	l.keys = r.indexKeysLocked(l, keys)
}

func (r *Relay) removeLink(l *agentLink) {
	r.mu.Lock()
	defer r.mu.Unlock()
	l.closed = true
	for i, cur := range r.links {
		if cur == l {
			r.links = append(r.links[:i], r.links[i+1:]...)
			break
		}
	}
	for hash, cur := range r.byKey {
		if cur == l {
			delete(r.byKey, hash)
		}
	}
}

// lookupKey находит узел по хешу ключа и возвращает ID и подпись ключа.
func (r *Relay) lookupKey(hash string) (*agentLink, string, string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	l, ok := r.byKey[hash]
	if !ok {
		return nil, "", "", false
	}
	if l.closed || l.sess.IsClosed() {
		delete(r.byKey, hash)
		return nil, "", "", false
	}
	for _, k := range l.keys {
		if k.Hash == hash {
			return l, k.ID, k.Label, true
		}
	}
	return l, "", "", true
}

// Пакет relay — шлюз на VPS2: принимает агентов и обслуживает SOCKS5.
package relay

import (
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"log"
	"net"
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
}

type agentLink struct {
	name    string
	version string
	remote  string
	since   time.Time
	keys    []protocol.Key
	sess    *yamux.Session
}

type Relay struct {
	cfg Config
	log *log.Logger

	mu    sync.Mutex
	links []*agentLink
	byKey map[string]*agentLink
}

func New(cfg Config, logger *log.Logger) *Relay {
	return &Relay{cfg: cfg, log: logger, byKey: make(map[string]*agentLink)}
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
				return
			}
			go r.handleTunnel(c)
		}
	}()
	r.log.Printf("приём агентов на %s", r.cfg.TunnelAddr)

	sln, err := net.Listen("tcp", r.cfg.SocksAddr)
	if err != nil {
		return fmt.Errorf("socks: %w", err)
	}
	defer sln.Close()
	r.log.Printf("SOCKS5 на %s", r.cfg.SocksAddr)

	return r.serveSocks(sln)
}

func (r *Relay) listenTunnel() (net.Listener, error) {
	if r.cfg.CertFile == "" {
		return net.Listen("tcp", r.cfg.TunnelAddr)
	}
	cert, err := tls.LoadX509KeyPair(r.cfg.CertFile, r.cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	return tls.Listen("tcp", r.cfg.TunnelAddr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
}

// handleTunnel принимает агента: проверяет токен, поднимает yamux
// и держит соединение, пока агент не отключится.
func (r *Relay) handleTunnel(c net.Conn) {
	remote := c.RemoteAddr().String()
	defer c.Close()

	c.SetDeadline(time.Now().Add(15 * time.Second))
	bc := protocol.NewBufConn(c)

	var hello protocol.Hello
	if err := protocol.ReadJSON(bc.R, &hello); err != nil {
		r.log.Printf("агент %s: нет приветствия: %v", remote, err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(hello.Token), []byte(r.cfg.Token)) != 1 {
		_ = protocol.WriteJSON(c, protocol.Ack{Error: "неверный токен"})
		r.log.Printf("агент %s: неверный токен", remote)
		return
	}
	if err := protocol.WriteJSON(c, protocol.Ack{OK: true}); err != nil {
		return
	}
	c.SetDeadline(time.Time{})

	sess, err := yamux.Server(bc, protocol.MuxConfig())
	if err != nil {
		r.log.Printf("агент %s: yamux: %v", remote, err)
		return
	}

	link := &agentLink{
		name:    hello.Name,
		version: hello.Version,
		remote:  remote,
		since:   time.Now(),
		keys:    hello.Keys,
		sess:    sess,
	}
	r.addLink(link)
	r.log.Printf("агент подключён: %s (%s, %s), ключей: %d", hello.Name, remote, hello.Version, len(hello.Keys))
	defer func() {
		r.removeLink(link)
		r.log.Printf("агент отключён: %s (%s)", hello.Name, remote)
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
		r.log.Printf("агент %s обновил ключи: %d", link.name, len(msg.Keys))
	}
}

func (r *Relay) setLinkKeys(l *agentLink, keys []protocol.Key) {
	r.mu.Lock()
	defer r.mu.Unlock()

	l.keys = keys
	for hash, cur := range r.byKey {
		if cur == l {
			delete(r.byKey, hash)
		}
	}
	for _, k := range keys {
		if k.Hash != "" {
			r.byKey[k.Hash] = l
		}
	}
}

// lookupKey находит узел по хешу ключа и возвращает подпись ключа.
func (r *Relay) lookupKey(hash string) (*agentLink, string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	l, ok := r.byKey[hash]
	if !ok || l.sess.IsClosed() {
		return nil, "", false
	}
	for _, k := range l.keys {
		if k.Hash == hash {
			return l, k.Label, true
		}
	}
	return l, "", true
}

func (r *Relay) addLink(l *agentLink) {
	r.mu.Lock()
	r.links = append(r.links, l)
	for _, k := range l.keys {
		if k.Hash != "" {
			r.byKey[k.Hash] = l
		}
	}
	r.mu.Unlock()
}

func (r *Relay) removeLink(l *agentLink) {
	r.mu.Lock()
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
	r.mu.Unlock()
}

// pickLink больше не нужен: маршрут выбирается по ключу доступа.

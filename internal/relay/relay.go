// Пакет relay — шлюз на VPS2: принимает агентов и обслуживает SOCKS5.
package relay

import (
	"crypto/subtle"
	"crypto/tls"
	"errors"
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
	SocksUser  string
	SocksPass  string
}

type agentLink struct {
	name    string
	version string
	remote  string
	since   time.Time
	sess    *yamux.Session
}

type Relay struct {
	cfg Config
	log *log.Logger

	mu    sync.Mutex
	links []*agentLink
	next  int
}

var errNoAgents = errors.New("нет подключённых узлов")

func New(cfg Config, logger *log.Logger) *Relay {
	return &Relay{cfg: cfg, log: logger}
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
		sess:    sess,
	}
	r.addLink(link)
	r.log.Printf("агент подключён: %s (%s, %s)", hello.Name, remote, hello.Version)
	defer func() {
		r.removeLink(link)
		r.log.Printf("агент отключён: %s (%s)", hello.Name, remote)
	}()

	<-sess.CloseChan()
}

func (r *Relay) addLink(l *agentLink) {
	r.mu.Lock()
	r.links = append(r.links, l)
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
	r.mu.Unlock()
}

// pickLink выбирает живой узел по кругу.
func (r *Relay) pickLink() (*agentLink, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	n := len(r.links)
	if n == 0 {
		return nil, errNoAgents
	}
	for i := 0; i < n; i++ {
		idx := (r.next + i) % n
		l := r.links[idx]
		if !l.sess.IsClosed() {
			r.next = (idx + 1) % n
			return l, nil
		}
	}
	return nil, errNoAgents
}

package relay

import (
	"net"
	"sync/atomic"
	"time"
)

// session — одно клиентское подключение через шлюз.
// GPT: нужно для панели: кто, куда и сколько передал.
type session struct {
	id     uint64
	agent  string
	client string
	host   string
	port   int
	since  time.Time
	in     atomic.Uint64
	out    atomic.Uint64
	link   *agentLink
}

func (r *Relay) trackSession(link *agentLink, client, host string, port int) *session {
	s := &session{
		agent:  link.name,
		client: client,
		host:   host,
		port:   port,
		since:  time.Now(),
		link:   link,
	}
	r.sessMu.Lock()
	r.nextID++
	s.id = r.nextID
	r.sessions[s.id] = s
	r.sessMu.Unlock()
	link.live.Add(1)
	return s
}

func (r *Relay) finishSession(s *session) {
	r.sessMu.Lock()
	delete(r.sessions, s.id)
	r.sessMu.Unlock()
	s.link.live.Add(-1)
}

// countConn считает трафик сессии и узла.
type countConn struct {
	net.Conn
	s    *session
	link *agentLink
}

func (c *countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.s.out.Add(uint64(n))
		c.link.out.Add(uint64(n))
	}
	return n, err
}

func (c *countConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.s.in.Add(uint64(n))
		c.link.in.Add(uint64(n))
	}
	return n, err
}

// AgentSnapshot — состояние одного подключённого узла.
type AgentSnapshot struct {
	Name     string
	Version  string
	Remote   string
	Since    time.Time
	Keys     int
	Sessions int64
	In       uint64
	Out      uint64
}

// SessionSnapshot — одно активное подключение.
type SessionSnapshot struct {
	ID     uint64
	Agent  string
	Client string
	Host   string
	Port   int
	Since  time.Time
	In     uint64
	Out    uint64
}

// Snapshot отдаёт состояние шлюза для панели.
func (r *Relay) Snapshot() ([]AgentSnapshot, []SessionSnapshot, uint64, uint64) {
	r.mu.Lock()
	agents := make([]AgentSnapshot, 0, len(r.links))
	var totalIn, totalOut uint64
	for _, l := range r.links {
		agents = append(agents, AgentSnapshot{
			Name:     l.name,
			Version:  l.version,
			Remote:   l.remote,
			Since:    l.since,
			Keys:     len(l.keys),
			Sessions: l.live.Load(),
			In:       l.in.Load(),
			Out:      l.out.Load(),
		})
		totalIn += l.in.Load()
		totalOut += l.out.Load()
	}
	r.mu.Unlock()

	r.sessMu.Lock()
	sessions := make([]SessionSnapshot, 0, len(r.sessions))
	for _, s := range r.sessions {
		sessions = append(sessions, SessionSnapshot{
			ID:     s.id,
			Agent:  s.agent,
			Client: s.client,
			Host:   s.host,
			Port:   s.port,
			Since:  s.since,
			In:     s.in.Load(),
			Out:    s.out.Load(),
		})
	}
	r.sessMu.Unlock()

	return agents, sessions, totalIn, totalOut
}

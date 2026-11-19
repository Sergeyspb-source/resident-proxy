// Пакет hop — простой TCP-проброс для второго узла.
// Клиент подключается к VPS1, VPS1 пересылает поток на VPS2.
// TLS клиента заканчивается на VPS2, поэтому hop видит только шифротекст.
package hop

import (
	"log"
	"net"
	"time"

	"exitnode/internal/protocol"
)

type Config struct {
	Listen   string
	Target   string
	MaxConns int
}

type Hop struct {
	cfg Config
	log *log.Logger
	sem chan struct{}
}

func New(cfg Config, logger *log.Logger) *Hop {
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 512
	}
	return &Hop{cfg: cfg, log: logger, sem: make(chan struct{}, cfg.MaxConns)}
}

func (h *Hop) Serve() error {
	ln, err := net.Listen("tcp", h.cfg.Listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	h.log.Printf("проброс %s -> %s", h.cfg.Listen, h.cfg.Target)

	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		select {
		case h.sem <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		go h.handle(c)
	}
}

func (h *Hop) handle(c net.Conn) {
	defer func() { <-h.sem }()
	defer c.Close()

	d := net.Dialer{Timeout: 10 * time.Second}
	u, err := d.Dial("tcp", h.cfg.Target)
	if err != nil {
		h.log.Printf("%s: %v", c.RemoteAddr(), err)
		return
	}
	defer u.Close()

	protocol.Join(c, u)
}

// Пакет client — локальный SOCKS5 для коллеги.
// Браузер не умеет передавать пароль в SOCKS5, поэтому клиент сам
// добавляет ключ при подключении к шлюзу.
package client

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"exitnode/internal/protocol"
)

type Config struct {
	Listen string
	Server string
	Key    string
	User   string
}

func Run(cfg Config, logger *log.Logger) error {
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	logger.Printf("локальный SOCKS5 на %s, шлюз %s", cfg.Listen, cfg.Server)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go handle(c, cfg, logger)
	}
}

func handle(c net.Conn, cfg Config, logger *log.Logger) {
	defer c.Close()
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

	up, err := dialUpstream(cfg, host, port)
	if err != nil {
		logger.Printf("%s:%d: %v", host, port, err)
		reply(c, 5)
		return
	}
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		up.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})

	protocol.Join(&protocol.BufConn{Conn: c, R: br}, up)
}

// dialUpstream проходит SOCKS5-рукопожатие со шлюзом, передавая ключ как пароль.
func dialUpstream(cfg Config, host string, port int) (net.Conn, error) {
	if len(cfg.Key) > 255 {
		return nil, errors.New("ключ слишком длинный")
	}

	d := net.Dialer{Timeout: 15 * time.Second}
	c, err := d.Dial("tcp", cfg.Server)
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

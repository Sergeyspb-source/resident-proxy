package relay

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"time"

	"github.com/hashicorp/yamux"

	"exitnode/internal/protocol"
)

// Константы SOCKS5 из RFC 1928 / RFC 1929.
const (
	socksVersion = 5

	authUserPass = 0x02
	authNoAccept = 0xff

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess            = 0x00
	repGeneralFailure     = 0x01
	repCommandUnsupported = 0x07
	repAddrUnsupported    = 0x08
)

func (r *Relay) serveSocks(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go r.handleSocks(c)
	}
}

// handleSocks обслуживает одного SOCKS5-клиента.
// GPT: домен передаётся агенту как есть (remote DNS), чтобы адрес резолвил
// узел выхода, а не клиент — иначе получаем DNS-leak и неверную геолокацию.
func (r *Relay) handleSocks(c net.Conn) {
	select {
	case r.socksSem <- struct{}{}:
		defer func() { <-r.socksSem }()
	default:
		_ = c.Close()
		return
	}

	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(c)

	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil {
		return
	}
	if head[0] != socksVersion {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}

	var client string
	// Доступ всегда по ключу: клиент присылает ключ в поле пароля,
	// шлюз ищет его хеш среди ключей подключённых узлов.
	if !hasByte(methods, authUserPass) {
		_, _ = c.Write([]byte{socksVersion, authNoAccept})
		return
	}
	if _, err := c.Write([]byte{socksVersion, authUserPass}); err != nil {
		return
	}
	user, pass, ok := readCreds(br)
	if !ok {
		_, _ = c.Write([]byte{1, 1})
		return
	}
	link, label, found := r.lookupKey(keyHash(pass))
	if !found {
		_, _ = c.Write([]byte{1, 1})
		r.log.Printf("SOCKS: неизвестный ключ (логин %q) от %s", user, c.RemoteAddr())
		return
	}
	if _, err := c.Write([]byte{1, 0}); err != nil {
		return
	}
	client = label

	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return
	}
	if req[0] != socksVersion {
		return
	}
	if req[1] != cmdConnect {
		socksReply(c, repCommandUnsupported)
		return
	}

	host, err := readAddr(br, req[3])
	if err != nil {
		socksReply(c, repAddrUnsupported)
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(br, portBuf); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(portBuf))

	st, err := r.open(link, protocol.OpenRequest{Host: host, Port: port, Client: client})
	if err != nil {
		code := byte(repGeneralFailure)
		var oe *protocol.OpenError
		if errors.As(err, &oe) && oe.Code != 0 {
			code = byte(oe.Code)
		}
		socksReply(c, code)
		r.log.Printf("SOCKS %q:%d: %v", host, port, err)
		return
	}
	if err := socksReplyOK(c); err != nil {
		st.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})

	protocol.Join(&protocol.BufConn{Conn: c, R: br}, st)
}

func (r *Relay) open(link *agentLink, req protocol.OpenRequest) (net.Conn, error) {
	type result struct {
		st  *yamux.Stream
		err error
	}

	// OpenStream может заблокироваться при переполненном backlog,
	// поэтому открываем поток асинхронно и ограничиваем ожидание.
	ch := make(chan result, 1)
	go func() {
		st, err := link.sess.OpenStream()
		ch <- result{st: st, err: err}
	}()

	var st *yamux.Stream
	select {
	case res := <-ch:
		if res.err != nil {
			return nil, res.err
		}
		st = res.st
	case <-time.After(10 * time.Second):
		go func() {
			if res := <-ch; res.st != nil {
				_ = res.st.Close()
			}
		}()
		return nil, errors.New("таймаут открытия потока")
	}

	st.SetDeadline(time.Now().Add(25 * time.Second))
	bc := protocol.NewBufConn(st)

	if err := protocol.WriteJSON(bc, req); err != nil {
		st.Close()
		return nil, err
	}

	var rep protocol.Reply
	if err := protocol.ReadJSON(bc.R, &rep); err != nil {
		st.Close()
		return nil, err
	}
	if !rep.OK {
		st.Close()
		code := rep.Code
		if code == 0 {
			code = protocol.CodeGeneral
		}
		msg := rep.Error
		if msg == "" {
			msg = "узел отклонил подключение"
		}
		return nil, &protocol.OpenError{Code: code, Message: msg}
	}

	st.SetDeadline(time.Time{})
	return bc, nil
}

func readCreds(br *bufio.Reader) (string, string, bool) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return "", "", false
	}
	if hdr[0] != 1 {
		return "", "", false
	}
	user := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(br, user); err != nil {
		return "", "", false
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(br, plen); err != nil {
		return "", "", false
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(br, pass); err != nil {
		return "", "", false
	}
	return string(user), string(pass), true
}

// keyHash — тот же хеш, что присылает агент в списке ключей.
func keyHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func readAddr(br *bufio.Reader, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case atypDomain:
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
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	}
	return "", errors.New("неизвестный тип адреса")
}

func hasByte(list []byte, v byte) bool {
	for _, b := range list {
		if b == v {
			return true
		}
	}
	return false
}

func socksReply(c net.Conn, code byte) {
	_, _ = c.Write([]byte{socksVersion, code, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
}

func socksReplyOK(c net.Conn) error {
	_, err := c.Write([]byte{socksVersion, repSuccess, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

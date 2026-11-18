// Пакет secure — шифрованный поток поверх соединения с relay.
// Ключ выводится из ключа доступа, которого у шлюза нет: он видит только хеш.
package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

const maxFrame = 64 << 10

// DeriveKey превращает ключ доступа в 32-байтный ключ AES.
func DeriveKey(value string) []byte {
	sum := sha256.Sum256([]byte("exitnode-e2e-v1|" + value))
	return sum[:]
}

// Conn шифрует каждый кадр AES-256-GCM.
type Conn struct {
	net.Conn
	aead cipher.AEAD
	wmu  sync.Mutex
	rbuf []byte
}

func NewConn(c net.Conn, key []byte) (*Conn, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Conn{Conn: c, aead: aead}, nil
}

func (c *Conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 32<<10 {
			n = 32 << 10
		}
		chunk := p[:n]

		nonce := make([]byte, c.aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return total, err
		}
		ct := c.aead.Seal(nil, nonce, chunk, nil)

		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(len(nonce)+len(ct)))
		if _, err := c.Conn.Write(hdr[:]); err != nil {
			return total, err
		}
		if _, err := c.Conn.Write(nonce); err != nil {
			return total, err
		}
		if _, err := c.Conn.Write(ct); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (c *Conn) Read(p []byte) (int, error) {
	if len(c.rbuf) == 0 {
		var hdr [4]byte
		if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
			return 0, err
		}
		size := int(binary.BigEndian.Uint32(hdr[:]))
		if size < c.aead.NonceSize()+c.aead.Overhead() || size > maxFrame {
			return 0, errors.New("secure: неверный размер кадра")
		}
		frame := make([]byte, size)
		if _, err := io.ReadFull(c.Conn, frame); err != nil {
			return 0, err
		}
		nonce := frame[:c.aead.NonceSize()]
		ct := frame[c.aead.NonceSize():]
		pt, err := c.aead.Open(nil, nonce, ct, nil)
		if err != nil {
			return 0, err
		}
		c.rbuf = pt
	}

	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

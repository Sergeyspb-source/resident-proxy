// Пакет protocol описывает управляющие сообщения между шлюзом и агентом.
// Соединение: TLS -> yamux -> поток на каждую сессию.
// Внутри потока: одна JSON-строка запроса, одна JSON-строка ответа, дальше сырые байты.
package protocol

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

const Version = "0.2.0"

// Коды ошибок совпадают с кодами SOCKS5 (RFC 1928), чтобы шлюз отдавал клиенту
// корректный ответ без дополнительного маппинга.
const (
	CodeGeneral     = 1
	CodeNotAllowed  = 2
	CodeUnreachable = 4
	CodeRefused     = 5
)

const maxControlLine = 64 << 10

// Hello отправляет агент сразу после установки TLS.
type Hello struct {
	Token   string `json:"token"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Keys    []Key  `json:"keys,omitempty"`
}

// Key — хеш ключа доступа. Сам ключ остаётся у владельца узла и не уходит на шлюз.
type Key struct {
	Label string `json:"label"`
	Hash  string `json:"hash"`
}

// Control — служебное сообщение агента после подключения.
type Control struct {
	Type string `json:"type"`
	Keys []Key  `json:"keys,omitempty"`
}

const ControlKeys = "keys"

// Ack подтверждает регистрацию агента на шлюзе.
type Ack struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// OpenRequest шлёт шлюз в поток, когда клиент сделал SOCKS5 CONNECT.
type OpenRequest struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Client string `json:"client,omitempty"`
}

// Reply возвращает агент: можно ли открывать соединение.
type Reply struct {
	OK    bool   `json:"ok"`
	Code  int    `json:"code,omitempty"`
	Error string `json:"error,omitempty"`
}

// OpenError несёт код SOCKS5 и текст причины.
type OpenError struct {
	Code    int
	Message string
}

func (e *OpenError) Error() string { return e.Message }

func WriteJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

func ReadJSON(r *bufio.Reader, v any) error {
	line, err := readControlLine(r)
	if err != nil {
		return err
	}
	return json.Unmarshal(line, v)
}

// readControlLine читает строку с жёстким лимитом.
// GPT: ReadBytes('\n') рос без ограничения — до проверки лимита,
// поэтому одно соединение без перевода строки могло съесть память.
func readControlLine(r *bufio.Reader) ([]byte, error) {
	buf := make([]byte, 0, 256)
	for {
		chunk, err := r.ReadSlice('\n')
		if len(buf)+len(chunk) > maxControlLine {
			return nil, fmt.Errorf("служебная строка слишком длинная")
		}
		buf = append(buf, chunk...)
		switch err {
		case nil:
			return buf, nil
		case bufio.ErrBufferFull:
			continue
		default:
			return nil, err
		}
	}
}

// BufConn сохраняет буферизованный reader: после чтения служебной строки
// в буфере могут остаться байты полезной нагрузки, и терять их нельзя.
type BufConn struct {
	net.Conn
	R *bufio.Reader
}

func NewBufConn(c net.Conn) *BufConn {
	return &BufConn{Conn: c, R: bufio.NewReader(c)}
}

func (b *BufConn) Read(p []byte) (int, error) { return b.R.Read(p) }

// MuxConfig — общие настройки yamux для обеих сторон.
// GPT: окно уменьшено до 1 МиБ и backlog до 64, чтобы поток с нечитаемыми
// данными не мог занять гигабайты памяти; таймаут открытия потока
// не даёт OpenStream висеть при переполненном backlog.
func MuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.MaxStreamWindowSize = 1 << 20
	cfg.AcceptBacklog = 64
	cfg.StreamOpenTimeout = 15 * time.Second
	cfg.StreamCloseTimeout = 10 * time.Second
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 20 * time.Second
	cfg.LogOutput = io.Discard
	return cfg
}

// Join гоняет байты в обе стороны и закрывает оба соединения,
// как только одно из направлений завершилось.
func Join(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(a, b)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(b, a)
		done <- struct{}{}
	}()
	<-done
	a.Close()
	b.Close()
	<-done
}

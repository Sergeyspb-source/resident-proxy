// Пакет agent — программа на ПК коллеги: держит туннель до шлюза,
// выполняет исходящие соединения и применяет лимиты конкретного ключа.
package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	mrand "math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hashicorp/yamux"
	"golang.org/x/time/rate"

	"exitnode/internal/desktop"
	"exitnode/internal/limits"
	"exitnode/internal/monitor"
	"exitnode/internal/protocol"
	"exitnode/internal/secure"
	"exitnode/internal/ui"
)

const dayLayout = "2006-01-02"

type Config struct {
	RelayAddr   string
	ServerName  string
	Token       string
	Name        string
	UIAddr      string
	AllowPorts  string
	MaxSessions int
	TrayMode    bool
	Insecure    bool
	NoTLS       bool
	QuotaMB     int64
	RateKBps    int64
	Domains     string
	PublicSocks string
	Version     string
	OnReady     func(url string)
}

type Agent struct {
	cfg     Config
	log     *log.Logger
	guard   *Guard
	reg     *monitor.Registry
	sys     *monitor.System
	started time.Time

	enabled   atomic.Bool
	inFlight  atomic.Int32
	keysDirty atomic.Bool
	saveMu    sync.Mutex

	stateMu       sync.Mutex
	keys          []limits.AccessKey
	defaultLimits limits.Values
	limiters      map[string]*rate.Limiter
	limPath       string
	limDirty      bool

	mu   sync.Mutex
	sess *yamux.Session

	ticks int
}

func New(cfg Config, logger *log.Logger) (*Agent, error) {
	guard, err := NewGuard(cfg.AllowPorts)
	if err != nil {
		return nil, err
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 8
	}
	if cfg.Name == "" {
		host, _ := os.Hostname()
		cfg.Name = host
	}

	a := &Agent{
		cfg:           cfg,
		log:           logger,
		guard:         guard,
		reg:           monitor.NewRegistry(),
		sys:           monitor.NewSystem(),
		started:       time.Now(),
		limiters:      make(map[string]*rate.Limiter),
		defaultLimits: limits.Normalize(limits.Values{QuotaMB: cfg.QuotaMB, RateKBps: cfg.RateKBps, Domains: cfg.Domains}),
		limPath:       statePath(),
	}

	migrated := false
	if a.limPath != "" {
		st, err := limits.Load(a.limPath)
		if err != nil && a.limPath != legacyStatePath() {
			if old, oldErr := limits.Load(legacyStatePath()); oldErr == nil {
				st, err = old, nil
				migrated = true
			}
		}
		if err == nil {
			a.keys = st.Keys
			a.defaultLimits = st.Values
			if migrated {
				// В старом формате лимиты были общими на узел.
				// Переносим их на ключи, у которых своих ещё нет.
				for i := range a.keys {
					if isZeroValues(a.keys[i].Limits) {
						a.keys[i].Limits = st.Values
					}
				}
			}
		} else {
			a.log.Printf("состояние не загружено: %v", err)
		}
	}

	a.stateMu.Lock()
	for i := range a.keys {
		a.rollKeyLocked(&a.keys[i])
	}
	a.stateMu.Unlock()

	if migrated {
		a.flushLimits()
		_ = os.Remove(legacyStatePath())
	}

	a.log.Printf("ключей: %d", len(a.keys))
	return a, nil
}

func isZeroValues(v limits.Values) bool {
	return v.QuotaMB == 0 && v.QuotaMonthMB == 0 && v.RateKBps == 0 && v.Domains == ""
}

func (a *Agent) Run() error {
	a.enabled.Store(true)

	go a.tickLoop()
	go a.connectLoop()

	onReady := func(url string) {
		a.log.Printf("панель: %s", url)
		if a.cfg.OnReady != nil {
			a.cfg.OnReady(url)
		}
	}
	return ui.Serve(a.cfg.UIAddr, a.reg, a, a.sys, a.log, onReady)
}

func (a *Agent) tickLoop() {
	tk := time.NewTicker(time.Second)
	defer tk.Stop()
	for range tk.C {
		a.reg.Tick()
		a.sys.Sample()
		a.ticks++
		if a.ticks%10 == 0 {
			a.notifyKeys()
		}
		if a.ticks%5 == 0 {
			a.flushLimits()
		}
	}
}

// connectLoop держит туннель: при обрыве переподключается с паузой и разбросом.
func (a *Agent) connectLoop() {
	backoff := time.Second
	for {
		start := time.Now()
		err := a.connectOnce()
		if err != nil {
			a.log.Printf("шлюз недоступен: %v", err)
		}
		if time.Since(start) > 30*time.Second {
			backoff = time.Second
		}
		delay := backoff
		if half := int64(backoff / 2); half > 0 {
			delay += time.Duration(mrand.Int64N(half))
		}
		time.Sleep(delay)
		backoff *= 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

func (a *Agent) connectOnce() error {
	d := net.Dialer{Timeout: 15 * time.Second}
	raw, err := d.Dial("tcp", a.cfg.RelayAddr)
	if err != nil {
		return err
	}
	defer raw.Close()

	if !a.cfg.NoTLS {
		serverName, err := tlsServerName(a.cfg.RelayAddr, a.cfg.ServerName)
		if err != nil {
			return err
		}
		cfg := &tls.Config{
			MinVersion:         tls.VersionTLS13,
			ServerName:         serverName,
			InsecureSkipVerify: a.cfg.Insecure,
		}
		tc := tls.Client(raw, cfg)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err = tc.HandshakeContext(ctx)
		cancel()
		if err != nil {
			return fmt.Errorf("TLS: %w", err)
		}
		raw = tc
	}

	if err := protocol.WriteJSON(raw, protocol.Hello{
		Token:   a.cfg.Token,
		Name:    a.cfg.Name,
		Version: protocol.Version,
		Keys:    a.keyHashes(),
	}); err != nil {
		return err
	}
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	bc := protocol.NewBufConn(raw)
	var ack protocol.Ack
	if err := protocol.ReadJSON(bc.R, &ack); err != nil {
		return err
	}
	if !ack.OK {
		if ack.Error == "" {
			ack.Error = "шлюз отклонил подключение"
		}
		return errors.New(ack.Error)
	}
	_ = raw.SetDeadline(time.Time{})

	sess, err := yamux.Client(bc, protocol.MuxConfig())
	if err != nil {
		return err
	}

	a.setSession(sess)
	a.log.Printf("подключено к шлюзу %s", a.cfg.RelayAddr)
	defer func() {
		a.setSession(nil)
		sess.Close()
	}()

	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return err
		}
		go a.handleStream(st)
	}
}

// tlsServerName берёт имя из адреса шлюза, если флаг не задан.
// GPT: tls.Client не подставляет имя хоста сам, и без ServerName
// проверка сертификата сводится к проверке цепочки без имени.
func tlsServerName(relayAddr, override string) (string, error) {
	if override != "" {
		return override, nil
	}
	host, _, err := net.SplitHostPort(relayAddr)
	if err != nil {
		return "", fmt.Errorf("не разобрать адрес шлюза: %w", err)
	}
	if host == "" {
		return "", errors.New("пустой адрес шлюза")
	}
	return host, nil
}

func (a *Agent) setSession(s *yamux.Session) {
	a.mu.Lock()
	a.sess = s
	a.mu.Unlock()
}

func (a *Agent) connected() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sess != nil && !a.sess.IsClosed()
}

func (a *Agent) session() *yamux.Session {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sess == nil || a.sess.IsClosed() {
		return nil
	}
	return a.sess
}

// handleStream обслуживает одну сессию: проверяет ключ и его лимиты,
// затем соединяется с целью и передаёт байты.
func (a *Agent) handleStream(st *yamux.Stream) {
	n := a.inFlight.Add(1)
	defer a.inFlight.Add(-1)

	bc := protocol.NewBufConn(st)
	if int(n) > a.cfg.MaxSessions {
		_ = protocol.WriteJSON(bc, protocol.Reply{Code: protocol.CodeNotAllowed, Error: "узел перегружен"})
		st.Close()
		return
	}
	_ = st.SetReadDeadline(time.Now().Add(15 * time.Second))

	var req protocol.OpenRequest
	if err := protocol.ReadJSON(bc.R, &req); err != nil {
		st.Close()
		return
	}

	if !a.enabled.Load() {
		_ = protocol.WriteJSON(bc, protocol.Reply{Code: protocol.CodeNotAllowed, Error: "узел выключен пользователем"})
		st.Close()
		return
	}

	a.stateMu.Lock()
	idx := a.findKeyLocked(req.KeyID)
	if idx < 0 {
		a.stateMu.Unlock()
		_ = protocol.WriteJSON(bc, protocol.Reply{Code: protocol.CodeNotAllowed, Error: "ключ отозван"})
		st.Close()
		return
	}
	key := &a.keys[idx]
	a.rollKeyLocked(key)
	over := key.OverQuota()
	domains := key.Limits.Domains
	label := key.Label
	keyValue := key.Value
	limiter := a.limiterForLocked(req.KeyID)
	a.stateMu.Unlock()

	if over {
		_ = protocol.WriteJSON(bc, protocol.Reply{Code: protocol.CodeNotAllowed, Error: "квота трафика исчерпана"})
		st.Close()
		return
	}
	if label != "" {
		req.Client = label
	}

	if req.Host == protocol.E2EHost {
		a.serveE2E(bc, st, req, keyValue, domains, limiter)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	addr, err := a.guard.Resolve(ctx, req.Host, req.Port, domains)
	if err != nil {
		code := protocol.CodeGeneral
		var oe *protocol.OpenError
		if errors.As(err, &oe) {
			code = oe.Code
		}
		// GPT: клиенту — общий текст, детали (какой адрес и почему)
		// остаются в локальном логе, чтобы не отдавать оракул.
		a.log.Printf("сессия отклонена: %v", err)
		_ = protocol.WriteJSON(bc, protocol.Reply{Code: code, Error: "запрос отклонён настройками узла"})
		st.Close()
		return
	}

	dialer := net.Dialer{Timeout: 15 * time.Second}
	target, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		a.log.Printf("не удалось подключиться к %q:%d: %v", req.Host, req.Port, err)
		_ = protocol.WriteJSON(bc, protocol.Reply{Code: dialCode(err), Error: "не удалось подключиться к цели"})
		st.Close()
		return
	}
	if tc, ok := target.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}

	if err := protocol.WriteJSON(bc, protocol.Reply{OK: true}); err != nil {
		target.Close()
		st.Close()
		return
	}
	_ = st.SetReadDeadline(time.Time{})

	sessCtx, sessCancel := context.WithCancel(context.Background())
	sess := a.reg.Add(req.Client, req.KeyID, req.Host, req.Port, bc, sessCancel)
	defer a.reg.Remove(sess.ID)

	metered := &meterConn{
		Conn: bc,
		onRead: func(n int64) {
			sess.AddIn(n)
			a.addTraffic(req.KeyID, n)
		},
		onWrite: func(n int64) {
			sess.AddOut(n)
			a.addTraffic(req.KeyID, n)
		},
		ctx:     sessCtx,
		limiter: limiter,
	}

	a.log.Printf("сессия #%d (%q): %q:%d", sess.ID, req.Client, req.Host, req.Port)
	protocol.Join(metered, target)
	a.log.Printf("сессия #%d закрыта: принято %s, отдано %s",
		sess.ID, humanBytes(sess.In()), humanBytes(sess.Out()))
}

// serveE2E обслуживает сквозное шифрование: шлюз видит только фиктивный
// адрес, настоящая цель приходит внутри шифрованного потока.
func (a *Agent) serveE2E(bc *protocol.BufConn, st *yamux.Stream, req protocol.OpenRequest, keyValue, domains string, limiter *rate.Limiter) {
	if err := protocol.WriteJSON(bc, protocol.Reply{OK: true}); err != nil {
		st.Close()
		return
	}
	_ = st.SetReadDeadline(time.Time{})

	sec, err := secure.NewConn(bc, secure.DeriveKey(keyValue))
	if err != nil {
		st.Close()
		return
	}
	sbc := protocol.NewBufConn(sec)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var inner protocol.E2EConnect
	if err := protocol.ReadJSON(sbc.R, &inner); err != nil {
		a.log.Printf("e2e: нет запроса цели: %v", err)
		sec.Close()
		return
	}
	if inner.Host == "" || inner.Port < 1 || inner.Port > 65535 {
		a.log.Printf("e2e: неверная цель")
		sec.Close()
		return
	}

	addr, err := a.guard.Resolve(ctx, inner.Host, inner.Port, domains)
	if err != nil {
		a.log.Printf("e2e отклонено: %v", err)
		sec.Close()
		return
	}

	dialer := net.Dialer{Timeout: 15 * time.Second}
	target, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		a.log.Printf("e2e: не удалось подключиться к %q:%d: %v", inner.Host, inner.Port, err)
		sec.Close()
		return
	}
	if tc, ok := target.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}

	sessCtx, sessCancel := context.WithCancel(context.Background())
	sess := a.reg.Add(req.Client, req.KeyID, inner.Host, inner.Port, bc, sessCancel)
	defer a.reg.Remove(sess.ID)

	metered := &meterConn{
		Conn: sbc,
		onRead: func(n int64) {
			sess.AddIn(n)
			a.addTraffic(req.KeyID, n)
		},
		onWrite: func(n int64) {
			sess.AddOut(n)
			a.addTraffic(req.KeyID, n)
		},
		ctx:     sessCtx,
		limiter: limiter,
	}

	a.log.Printf("сессия #%d (e2e, %q): %q:%d", sess.ID, req.Client, inner.Host, inner.Port)
	protocol.Join(metered, target)
	a.log.Printf("сессия #%d закрыта: принято %s, отдано %s",
		sess.ID, humanBytes(sess.In()), humanBytes(sess.Out()))
}

func dialCode(err error) int {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return protocol.CodeRefused
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return protocol.CodeUnreachable
	default:
		return protocol.CodeGeneral
	}
}

// meterConn считает байты в момент передачи, чтобы скорость обновлялась вживую,
// и попутно тормозит поток до лимита конкретного ключа.
type meterConn struct {
	net.Conn
	onRead  func(int64)
	onWrite func(int64)
	ctx     context.Context
	limiter *rate.Limiter
}

func (m *meterConn) wait(n int) {
	if m.limiter == nil || n <= 0 {
		return
	}
	_ = m.limiter.WaitN(m.ctx, n)
}

func (m *meterConn) Read(p []byte) (int, error) {
	n, err := m.Conn.Read(p)
	if n > 0 {
		m.onRead(int64(n))
	}
	return n, err
}

func (m *meterConn) Write(p []byte) (int, error) {
	m.wait(len(p))
	n, err := m.Conn.Write(p)
	if n > 0 {
		m.onWrite(int64(n))
	}
	return n, err
}

// Info реализует ui.Controller.
func (a *Agent) Info() ui.Info {
	return ui.Info{
		Name:        a.cfg.Name,
		Relay:       a.cfg.RelayAddr,
		Connected:   a.connected(),
		Enabled:     a.enabled.Load(),
		Since:       a.started,
		MaxSessions: a.cfg.MaxSessions,
		PublicSocks: a.cfg.PublicSocks,
		Version:     a.cfg.Version,
	}
}

func (a *Agent) SetEnabled(v bool) { a.enabled.Store(v) }

func (a *Agent) KillAll() { a.reg.KillAll() }

// AgentInvite отдаёт данные для установки ещё одного узла.
func (a *Agent) AgentInvite() (relay, token, publicSocks string) {
	return a.cfg.RelayAddr, a.cfg.Token, a.cfg.PublicSocks
}

// Autostart показывает и меняет запись в автозагрузке Windows.
func (a *Agent) Autostart() bool { return desktop.AutostartEnabled() }

func (a *Agent) SetAutostart(v bool) error { return desktop.SetAutostart(v) }

// Keys отдаёт панели список пользователей. Значения ключей замаскированы.
func (a *Agent) Keys() []ui.KeyView {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()

	out := make([]ui.KeyView, 0, len(a.keys))
	for i := range a.keys {
		a.rollKeyLocked(&a.keys[i])
		out = append(out, keyView(&a.keys[i]))
	}
	return out
}

// KeyValue возвращает полный ключ по запросу из панели.
func (a *Agent) KeyValue(id string) (string, error) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	idx := a.findKeyLocked(id)
	if idx < 0 {
		return "", errors.New("ключ не найден")
	}
	return a.keys[idx].Value, nil
}

// AddKey создаёт ключ доступа и сразу сообщает его шлюзу.
func (a *Agent) AddKey(label string) (ui.KeyView, error) {
	label = strings.TrimSpace(label)
	if label == "" {
		return ui.KeyView{}, errors.New("нужна подпись, чтобы отличать коллег")
	}
	if len([]rune(label)) > 40 {
		label = string([]rune(label)[:40])
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return ui.KeyView{}, err
	}
	value := base64.RawURLEncoding.EncodeToString(buf)

	idBuf := make([]byte, 8)
	if _, err := rand.Read(idBuf); err != nil {
		return ui.KeyView{}, err
	}

	a.stateMu.Lock()
	if len(a.keys) >= 100 {
		a.stateMu.Unlock()
		return ui.KeyView{}, errors.New("слишком много ключей")
	}
	now := time.Now()
	key := limits.AccessKey{
		ID:     base64.RawURLEncoding.EncodeToString(idBuf),
		Label:  label,
		Value:  value,
		Limits: a.defaultLimits,
		Day:    now.Format(dayLayout),
		Month:  now.Format("2006-01"),
	}
	a.keys = append(a.keys, key)
	a.limDirty = true
	view := keyView(&a.keys[len(a.keys)-1])
	a.stateMu.Unlock()

	a.keysDirty.Store(true)
	a.saveState()
	a.notifyKeys()
	a.log.Printf("добавлен ключ доступа: %s", label)
	return view, nil
}

// RemoveKey отзывает ключ: шлюз перестаёт пускать его владельца.
func (a *Agent) RemoveKey(id string) error {
	a.stateMu.Lock()
	found := -1
	for i := range a.keys {
		if a.keys[i].ID == id {
			found = i
			break
		}
	}
	if found >= 0 {
		a.keys = append(a.keys[:found], a.keys[found+1:]...)
		delete(a.limiters, id)
	}
	a.limDirty = true
	a.stateMu.Unlock()

	if found < 0 {
		return errors.New("ключ не найден")
	}
	a.keysDirty.Store(true)
	a.saveState()
	a.notifyKeys()
	a.log.Printf("ключ отозван: %s", id)
	return nil
}

// SetKeyLimits применяет сайты, квоты и скорость конкретного пользователя.
func (a *Agent) SetKeyLimits(id string, v ui.KeyLimits) (ui.KeyView, error) {
	norm := limits.Normalize(limits.Values{
		QuotaMB:      v.QuotaMB,
		QuotaMonthMB: v.QuotaMonthMB,
		RateKBps:     v.RateKBps,
		Domains:      v.Domains,
	})

	a.stateMu.Lock()
	idx := a.findKeyLocked(id)
	if idx < 0 {
		a.stateMu.Unlock()
		return ui.KeyView{}, errors.New("ключ не найден")
	}
	key := &a.keys[idx]
	key.Limits = norm
	key.QuotaNotified = false
	if l, ok := a.limiters[id]; ok {
		applyRate(l, norm.RateKBps)
	}
	over := key.OverQuota()
	view := keyView(key)
	a.limDirty = true
	a.stateMu.Unlock()

	a.flushLimits()
	if over {
		a.reg.KillByKey(id)
	}
	a.log.Printf("лимиты обновлены: квота %d/%d МБ, скорость %d КБ/с, доменов: %d",
		norm.QuotaMB, norm.QuotaMonthMB, norm.RateKBps, len(limits.DomainList(norm.Domains)))
	return view, nil
}

func keyView(k *limits.AccessKey) ui.KeyView {
	return ui.KeyView{
		ID:              k.ID,
		Label:           k.Label,
		Value:           maskKey(k.Value),
		QuotaMB:         k.Limits.QuotaMB,
		QuotaMonthMB:    k.Limits.QuotaMonthMB,
		RateKBps:        k.Limits.RateKBps,
		Domains:         k.Limits.Domains,
		UsedBytes:       k.Used,
		UsedMonthBytes:  k.UsedMonth,
		QuotaBytes:      k.Limits.QuotaBytes(),
		QuotaMonthBytes: k.Limits.QuotaMonthBytes(),
	}
}

func maskKey(v string) string {
	if len(v) <= 12 {
		return v
	}
	return v[:4] + "…" + v[len(v)-4:]
}

func (a *Agent) findKeyLocked(id string) int {
	for i := range a.keys {
		if a.keys[i].ID == id {
			return i
		}
	}
	return -1
}

func (a *Agent) rollKeyLocked(k *limits.AccessKey) {
	now := time.Now()
	today := now.Format(dayLayout)
	month := now.Format("2006-01")
	if k.Day != today {
		k.Day = today
		k.Used = 0
		k.QuotaNotified = false
		a.limDirty = true
	}
	if k.Month != month {
		k.Month = month
		k.UsedMonth = 0
		k.QuotaNotified = false
		a.limDirty = true
	}
}

// limiterForLocked возвращает лимитер ключа; stateMu должен быть захвачен.
func (a *Agent) limiterForLocked(id string) *rate.Limiter {
	l, ok := a.limiters[id]
	if !ok {
		l = rate.NewLimiter(rate.Inf, 64<<10)
		a.limiters[id] = l
	}
	if idx := a.findKeyLocked(id); idx >= 0 {
		applyRate(l, a.keys[idx].Limits.RateKBps)
	}
	return l
}

func applyRate(l *rate.Limiter, kbps int64) {
	if kbps <= 0 {
		l.SetLimit(rate.Inf)
		l.SetBurst(64 << 10)
		return
	}
	r := rate.Limit(kbps * 1024)
	burst := int(r / 4)
	if burst < 64<<10 {
		burst = 64 << 10
	}
	if burst > 1<<20 {
		burst = 1 << 20
	}
	l.SetLimit(r)
	l.SetBurst(burst)
}

func (a *Agent) addTraffic(keyID string, n int64) {
	if n <= 0 || keyID == "" {
		return
	}

	a.stateMu.Lock()
	idx := a.findKeyLocked(keyID)
	if idx < 0 {
		a.stateMu.Unlock()
		return
	}
	key := &a.keys[idx]
	a.rollKeyLocked(key)
	key.Used += n
	key.UsedMonth += n
	over := key.OverQuota() && !key.QuotaNotified
	label := key.Label
	if over {
		key.QuotaNotified = true
	}
	a.limDirty = true
	a.stateMu.Unlock()

	if over {
		a.log.Printf("квота исчерпана у пользователя %q, сессии остановлены", label)
		a.reg.KillByKey(keyID)
		// GPT: при достижении квоты сразу пишем состояние на диск,
		// чтобы перезапуск не обнулил счётчик.
		a.flushLimits()
	}
}

func (a *Agent) keyHashes() []protocol.Key {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	out := make([]protocol.Key, 0, len(a.keys))
	for i := range a.keys {
		k := &a.keys[i]
		out = append(out, protocol.Key{ID: k.ID, Label: k.Label, Hash: keyHash(k.Value)})
	}
	return out
}

func keyHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (a *Agent) saveState() {
	a.stateMu.Lock()
	a.limDirty = true
	a.stateMu.Unlock()
	a.flushLimits()
}

// notifyKeys отправляет шлюзу актуальный список ключей без разрыва туннеля.
// Повторяется по таймеру, пока шлюз не подтвердит доставку.
func (a *Agent) notifyKeys() {
	if !a.keysDirty.Load() {
		return
	}
	sess := a.session()
	if sess == nil {
		a.log.Printf("ключи: туннель не открыт")
		return
	}
	st, err := sess.OpenStream()
	if err != nil {
		a.log.Printf("ключи: не открыть поток: %v", err)
		return
	}
	defer st.Close()
	_ = st.SetWriteDeadline(time.Now().Add(5 * time.Second))
	keys := a.keyHashes()
	if err := protocol.WriteJSON(st, protocol.Control{Type: protocol.ControlKeys, Keys: keys}); err != nil {
		a.log.Printf("ключи: не отправить: %v", err)
		return
	}
	a.keysDirty.Store(false)
	a.log.Printf("ключи отправлены: %d", len(keys))
}

func (a *Agent) flushLimits() {
	a.stateMu.Lock()
	if !a.limDirty || a.limPath == "" {
		a.stateMu.Unlock()
		return
	}
	st := limits.State{
		Values: a.defaultLimits,
		Keys:   append([]limits.AccessKey(nil), a.keys...),
	}
	a.limDirty = false
	a.stateMu.Unlock()

	// GPT: несколько горутин писали в один tmp-файл и могли оставить битый JSON.
	a.saveMu.Lock()
	err := limits.Save(a.limPath, st)
	a.saveMu.Unlock()

	if err != nil {
		a.log.Printf("не удалось сохранить состояние: %v", err)
		a.stateMu.Lock()
		a.limDirty = true
		a.stateMu.Unlock()
	}
}

// statePath хранит состояние в приватном каталоге пользователя.
// GPT: рядом с exe файл мог оказаться в Downloads или Program Files,
// где права наследуются от каталога и ключи читаются другими пользователями.
func statePath() string {
	if dir, err := os.UserCacheDir(); err == nil {
		base := filepath.Join(dir, "exitnode")
		if err := os.MkdirAll(base, 0o700); err == nil {
			return filepath.Join(base, "agent-state.json")
		}
	}
	return legacyStatePath()
}

func legacyStatePath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), "agent-state.json")
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d Б", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cБ", float64(n)/float64(div), "КМГТП"[exp])
}

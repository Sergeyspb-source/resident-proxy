// Пакет agent — программа на ПК коллеги: держит туннель до шлюза,
// выполняет исходящие соединения и показывает всё в локальной панели.
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
	OnReady     func(url string)
}

type Agent struct {
	cfg     Config
	log     *log.Logger
	guard   *Guard
	reg     *monitor.Registry
	sys     *monitor.System
	started time.Time

	enabled atomic.Bool
	limiter *rate.Limiter

	mu   sync.Mutex
	sess *yamux.Session

	keysMu sync.Mutex
	keys   []limits.AccessKey

	limMu       sync.Mutex
	limits      limits.Values
	used        int64
	usedDay     string
	usedMonth   int64
	usedMonthAt string
	limPath     string
	limDirty    bool
	quotaLogged bool
	ticks       int

	inFlight  atomic.Int32
	keysDirty atomic.Bool
	saveMu    sync.Mutex
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
		cfg:     cfg,
		log:     logger,
		guard:   guard,
		reg:     monitor.NewRegistry(),
		sys:     monitor.NewSystem(),
		started: time.Now(),
		limiter: rate.NewLimiter(rate.Inf, 64<<10),
		limits: limits.Normalize(limits.Values{
			QuotaMB:  cfg.QuotaMB,
			RateKBps: cfg.RateKBps,
			Domains:  cfg.Domains,
		}),
		usedDay: time.Now().Format(dayLayout),
		limPath: statePath(),
	}

	if a.limPath != "" {
		migrated := false
		st, err := limits.Load(a.limPath)
		if err != nil && a.limPath != legacyStatePath() {
			if old, oldErr := limits.Load(legacyStatePath()); oldErr == nil {
				st, err = old, nil
				a.limDirty = true
				migrated = true
			}
		}
		if err == nil {
			a.limits = st.Values
			a.used = st.Used
			a.usedMonth = st.UsedMonth
			a.keys = st.Keys
			if st.Day != "" {
				a.usedDay = st.Day
			}
			if st.Month != "" {
				a.usedMonthAt = st.Month
			}
		} else {
			a.log.Printf("состояние не загружено: %v", err)
		}
		if migrated {
			// Переносим состояние в приватный каталог и убираем старую копию
			// с ключами из папки программы.
			a.flushLimits()
			_ = os.Remove(legacyStatePath())
		}
	}

	a.limMu.Lock()
	a.rollLocked()
	a.applyLimitsLocked()
	a.limMu.Unlock()

	a.log.Printf("ограничения: квота %d МБ/сутки, скорость %d КБ/с, доменов в списке: %d",
		a.limits.QuotaMB, a.limits.RateKBps, len(limits.DomainList(a.limits.Domains)))

	return a, nil
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

// connectLoop держит туннель: при обрыве переподключается с паузой.
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

// handleStream обслуживает одну сессию: проверка, соединение с целью, передача байтов.
func (a *Agent) handleStream(st *yamux.Stream) {
	n := a.inFlight.Add(1)
	defer a.inFlight.Add(-1)

	bc := protocol.NewBufConn(st)
	if int(n) > a.cfg.MaxSessions {
		_ = protocol.WriteJSON(bc, protocol.Reply{
			Code:  protocol.CodeNotAllowed,
			Error: "узел перегружен",
		})
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
		_ = protocol.WriteJSON(bc, protocol.Reply{
			Code:  protocol.CodeNotAllowed,
			Error: "узел выключен пользователем",
		})
		st.Close()
		return
	}
	if a.overQuota() {
		_ = protocol.WriteJSON(bc, protocol.Reply{
			Code:  protocol.CodeNotAllowed,
			Error: "суточная квота трафика исчерпана",
		})
		st.Close()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	addr, err := a.guard.Resolve(ctx, req.Host, req.Port)
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
	sess := a.reg.Add(req.Client, req.Host, req.Port, bc, sessCancel)
	defer a.reg.Remove(sess.ID)

	metered := &meterConn{
		Conn: bc,
		onRead: func(n int64) {
			sess.AddIn(n)
			a.addTraffic(n)
		},
		onWrite: func(n int64) {
			sess.AddOut(n)
			a.addTraffic(n)
		},
		ctx:     sessCtx,
		limiter: a.limiter,
	}

	a.log.Printf("сессия #%d: %q:%d", sess.ID, req.Host, req.Port)
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
// и попутно тормозит поток до заданного лимита.
// GPT: ожидание лимитера привязано к контексту сессии, иначе после закрытия
// потока горутина висела бы в WaitN до пополнения токенов.
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
	}
}

func (a *Agent) SetEnabled(v bool) { a.enabled.Store(v) }

func (a *Agent) KillAll() { a.reg.KillAll() }

// Keys отдаёт панели список ключей. Сами значения не отдаются:
// их можно получить только отдельным запросом по конкретному ключу.
func (a *Agent) Keys() []ui.KeyView {
	a.keysMu.Lock()
	defer a.keysMu.Unlock()
	out := make([]ui.KeyView, 0, len(a.keys))
	for _, k := range a.keys {
		out = append(out, ui.KeyView{ID: k.ID, Label: k.Label, Value: maskKey(k.Value)})
	}
	return out
}

// KeyValue возвращает полный ключ по запросу из панели.
func (a *Agent) KeyValue(id string) (string, error) {
	a.keysMu.Lock()
	defer a.keysMu.Unlock()
	for _, k := range a.keys {
		if k.ID == id {
			return k.Value, nil
		}
	}
	return "", errors.New("ключ не найден")
}

func maskKey(v string) string {
	if len(v) <= 12 {
		return v
	}
	return v[:4] + "…" + v[len(v)-4:]
}

// AddKey создаёт ключ доступа и сразу сообщает его шлюзу.
func (a *Agent) AddKey(label string) (ui.KeyView, error) {
	label = strings.TrimSpace(label)
	if label == "" {
		return ui.KeyView{}, errors.New("нужна подпись, чтобы отличать коллег")
	}
	if len(label) > 40 {
		label = label[:40]
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return ui.KeyView{}, err
	}
	value := base64.RawURLEncoding.EncodeToString(buf)

	a.keysMu.Lock()
	if len(a.keys) >= 100 {
		a.keysMu.Unlock()
		return ui.KeyView{}, errors.New("слишком много ключей")
	}
	idBuf := make([]byte, 8)
	if _, err := rand.Read(idBuf); err != nil {
		a.keysMu.Unlock()
		return ui.KeyView{}, err
	}
	key := limits.AccessKey{
		ID:    base64.RawURLEncoding.EncodeToString(idBuf),
		Label: label,
		Value: value,
	}
	a.keys = append(a.keys, key)
	a.keysMu.Unlock()

	a.keysDirty.Store(true)
	a.saveState()
	a.notifyKeys()
	a.log.Printf("добавлен ключ доступа: %s", label)
	return ui.KeyView{ID: key.ID, Label: key.Label, Value: key.Value}, nil
}

// RemoveKey отзывает ключ: шлюз перестаёт пускать его владельца.
func (a *Agent) RemoveKey(id string) error {
	a.keysMu.Lock()
	found := false
	out := a.keys[:0]
	for _, k := range a.keys {
		if k.ID == id {
			found = true
			continue
		}
		out = append(out, k)
	}
	a.keys = out
	a.keysMu.Unlock()

	if !found {
		return errors.New("ключ не найден")
	}
	a.keysDirty.Store(true)
	a.saveState()
	a.notifyKeys()
	a.log.Printf("ключ отозван: %s", id)
	return nil
}

func (a *Agent) keyHashes() []protocol.Key {
	a.keysMu.Lock()
	defer a.keysMu.Unlock()
	out := make([]protocol.Key, 0, len(a.keys))
	for _, k := range a.keys {
		out = append(out, protocol.Key{Label: k.Label, Hash: keyHash(k.Value)})
	}
	return out
}

func keyHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (a *Agent) saveState() {
	a.limMu.Lock()
	a.limDirty = true
	a.limMu.Unlock()
	a.flushLimits()
}

// notifyKeys отправляет шлюзу актуальный список хешей без разрыва туннеля.
// Повторяется по таймеру, пока шлюз не подтвердит доставку.
func (a *Agent) notifyKeys() {
	if !a.keysDirty.Load() {
		return
	}
	sess := a.session()
	if sess == nil {
		return
	}
	st, err := sess.OpenStream()
	if err != nil {
		return
	}
	defer st.Close()
	_ = st.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := protocol.WriteJSON(st, protocol.Control{Type: protocol.ControlKeys, Keys: a.keyHashes()}); err != nil {
		return
	}
	a.keysDirty.Store(false)
}

func (a *Agent) session() *yamux.Session {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sess == nil || a.sess.IsClosed() {
		return nil
	}
	return a.sess
}

// Autostart показывает и меняет запись в автозагрузке Windows.
func (a *Agent) Autostart() bool { return desktop.AutostartEnabled() }

func (a *Agent) SetAutostart(v bool) error { return desktop.SetAutostart(v) }

// Limits отдаёт панели текущие настройки и расход.
func (a *Agent) Limits() ui.LimitsView {
	a.limMu.Lock()
	defer a.limMu.Unlock()
	a.rollLocked()
	return ui.LimitsView{
		QuotaMB:         a.limits.QuotaMB,
		QuotaMonthMB:    a.limits.QuotaMonthMB,
		RateKBps:        a.limits.RateKBps,
		Domains:         a.limits.Domains,
		UsedBytes:       a.used,
		QuotaBytes:      a.limits.QuotaBytes(),
		UsedMonthBytes:  a.usedMonth,
		QuotaMonthBytes: a.limits.QuotaMonthBytes(),
	}
}

// SetLimits применяет настройки сразу, без перезапуска, и сохраняет их на диск.
func (a *Agent) SetLimits(v ui.LimitsView) error {
	if v.QuotaMB < 0 || v.QuotaMonthMB < 0 || v.RateKBps < 0 {
		return errors.New("значения не могут быть отрицательными")
	}
	norm := limits.Normalize(limits.Values{
		QuotaMB:      v.QuotaMB,
		QuotaMonthMB: v.QuotaMonthMB,
		RateKBps:     v.RateKBps,
		Domains:      v.Domains,
	})

	a.limMu.Lock()
	a.limits = norm
	a.quotaLogged = false
	a.applyLimitsLocked()
	a.limDirty = true
	over := a.overQuotaLocked()
	a.limMu.Unlock()

	a.flushLimits()
	if over {
		a.reg.KillAll()
	}
	a.log.Printf("ограничения обновлены: квота %d МБ/сутки и %d МБ/месяц, скорость %d КБ/с, доменов: %d",
		norm.QuotaMB, norm.QuotaMonthMB, norm.RateKBps, len(limits.DomainList(norm.Domains)))
	return nil
}

func (a *Agent) addTraffic(n int64) {
	if n <= 0 {
		return
	}
	a.limMu.Lock()
	a.rollLocked()
	a.used += n
	a.usedMonth += n
	over := a.overQuotaLocked() && !a.quotaLogged
	if over {
		a.quotaLogged = true
	}
	a.limDirty = true
	a.limMu.Unlock()

	if over {
		a.log.Printf("квота исчерпана, все подключения остановлены")
		a.reg.KillAll()
		// GPT: при достижении квоты сразу пишем состояние на диск,
		// чтобы перезапуск не обнулил счётчик.
		a.flushLimits()
	}
}

func (a *Agent) overQuota() bool {
	a.limMu.Lock()
	defer a.limMu.Unlock()
	a.rollLocked()
	return a.overQuotaLocked()
}

func (a *Agent) overQuotaLocked() bool {
	qDay := a.limits.QuotaBytes()
	qMonth := a.limits.QuotaMonthBytes()
	overDay := qDay > 0 && a.used >= qDay
	overMonth := qMonth > 0 && a.usedMonth >= qMonth
	return overDay || overMonth
}

// rollLocked сбрасывает расход при смене суток и месяца.
func (a *Agent) rollLocked() {
	now := time.Now()
	today := now.Format(dayLayout)
	month := now.Format("2006-01")

	if a.usedDay != today {
		a.usedDay = today
		a.used = 0
		a.quotaLogged = false
		a.limDirty = true
	}
	if a.usedMonthAt != month {
		a.usedMonthAt = month
		a.usedMonth = 0
		a.quotaLogged = false
		a.limDirty = true
	}
}

func (a *Agent) applyLimitsLocked() {
	a.guard.SetDomains(a.limits.Domains)

	if a.limits.RateKBps <= 0 {
		a.limiter.SetLimit(rate.Inf)
		a.limiter.SetBurst(64 << 10)
		return
	}
	r := rate.Limit(a.limits.RateKBps * 1024)
	burst := int(r / 4)
	if burst < 64<<10 {
		burst = 64 << 10
	}
	if burst > 1<<20 {
		burst = 1 << 20
	}
	a.limiter.SetLimit(r)
	a.limiter.SetBurst(burst)
}

func (a *Agent) flushLimits() {
	a.limMu.Lock()
	if !a.limDirty || a.limPath == "" {
		a.limMu.Unlock()
		return
	}
	a.keysMu.Lock()
	keys := append([]limits.AccessKey(nil), a.keys...)
	a.keysMu.Unlock()

	st := limits.State{
		Values:    a.limits,
		Keys:      keys,
		Used:      a.used,
		UsedMonth: a.usedMonth,
		Day:       a.usedDay,
		Month:     a.usedMonthAt,
	}
	a.limDirty = false
	a.limMu.Unlock()

	// GPT: несколько горутин писали в один tmp-файл и могли оставить битый JSON.
	a.saveMu.Lock()
	err := limits.Save(a.limPath, st)
	a.saveMu.Unlock()

	if err != nil {
		a.log.Printf("не удалось сохранить настройки: %v", err)
		a.limMu.Lock()
		a.limDirty = true
		a.limMu.Unlock()
	}
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

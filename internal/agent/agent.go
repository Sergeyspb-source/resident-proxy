// Пакет agent — программа на ПК коллеги: держит туннель до шлюза,
// выполняет исходящие соединения и показывает всё в локальной панели.
package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hashicorp/yamux"
	"golang.org/x/time/rate"

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
	OpenBrowser bool
	Insecure    bool
	NoTLS       bool
	QuotaMB     int64
	RateKBps    int64
	Domains     string
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

	limMu       sync.Mutex
	limits      limits.Values
	used        int64
	usedDay     string
	limPath     string
	limDirty    bool
	quotaLogged bool
	ticks       int
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
		if st, err := limits.Load(a.limPath); err == nil {
			a.limits = st.Values
			a.used = st.Used
			if st.Day != "" {
				a.usedDay = st.Day
			}
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

// statePath хранит настройки рядом с exe, чтобы они переживали перезапуск.
func statePath() string {
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
		if a.cfg.OpenBrowser {
			openBrowser(url)
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
		time.Sleep(backoff)
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
		cfg := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: a.cfg.Insecure,
		}
		if a.cfg.ServerName != "" {
			cfg.ServerName = a.cfg.ServerName
		}
		tc := tls.Client(raw, cfg)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := tc.HandshakeContext(ctx)
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
	bc := protocol.NewBufConn(st)
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
	if a.reg.Count() >= a.cfg.MaxSessions {
		_ = protocol.WriteJSON(bc, protocol.Reply{
			Code:  protocol.CodeNotAllowed,
			Error: "достигнут лимит одновременных подключений",
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
		_ = protocol.WriteJSON(bc, protocol.Reply{Code: code, Error: err.Error()})
		st.Close()
		return
	}

	dialer := net.Dialer{Timeout: 15 * time.Second}
	target, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		_ = protocol.WriteJSON(bc, protocol.Reply{Code: dialCode(err), Error: err.Error()})
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

	sess := a.reg.Add(req.Client, req.Host, req.Port, bc)
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
		throttle: a.throttle,
	}

	a.log.Printf("сессия #%d: %s:%d", sess.ID, req.Host, req.Port)
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
type meterConn struct {
	net.Conn
	onRead   func(int64)
	onWrite  func(int64)
	throttle func(int)
}

func (m *meterConn) Read(p []byte) (int, error) {
	n, err := m.Conn.Read(p)
	if n > 0 {
		m.onRead(int64(n))
		if m.throttle != nil {
			m.throttle(n)
		}
	}
	return n, err
}

func (m *meterConn) Write(p []byte) (int, error) {
	if len(p) > 0 && m.throttle != nil {
		m.throttle(len(p))
	}
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

// Limits отдаёт панели текущие настройки и расход за сегодня.
func (a *Agent) Limits() ui.LimitsView {
	a.limMu.Lock()
	defer a.limMu.Unlock()
	a.rollLocked()
	return ui.LimitsView{
		QuotaMB:    a.limits.QuotaMB,
		RateKBps:   a.limits.RateKBps,
		Domains:    a.limits.Domains,
		UsedBytes:  a.used,
		QuotaBytes: a.limits.QuotaBytes(),
	}
}

// SetLimits применяет настройки сразу, без перезапуска, и сохраняет их на диск.
func (a *Agent) SetLimits(v ui.LimitsView) error {
	if v.QuotaMB < 0 || v.RateKBps < 0 {
		return errors.New("значения не могут быть отрицательными")
	}
	norm := limits.Normalize(limits.Values{
		QuotaMB:  v.QuotaMB,
		RateKBps: v.RateKBps,
		Domains:  v.Domains,
	})

	a.limMu.Lock()
	a.limits = norm
	a.quotaLogged = false
	a.applyLimitsLocked()
	a.limDirty = true
	over := norm.QuotaBytes() > 0 && a.used >= norm.QuotaBytes()
	a.limMu.Unlock()

	a.flushLimits()
	if over {
		a.reg.KillAll()
	}
	a.log.Printf("ограничения обновлены: квота %d МБ, скорость %d КБ/с, доменов: %d",
		norm.QuotaMB, norm.RateKBps, len(limits.DomainList(norm.Domains)))
	return nil
}

func (a *Agent) throttle(n int) {
	if n <= 0 {
		return
	}
	_ = a.limiter.WaitN(context.Background(), n)
}

func (a *Agent) addTraffic(n int64) {
	if n <= 0 {
		return
	}
	a.limMu.Lock()
	a.rollLocked()
	a.used += n
	quota := a.limits.QuotaBytes()
	over := quota > 0 && a.used >= quota && !a.quotaLogged
	if over {
		a.quotaLogged = true
	}
	a.limDirty = true
	a.limMu.Unlock()

	if over {
		a.log.Printf("суточная квота исчерпана, все подключения остановлены")
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
	q := a.limits.QuotaBytes()
	return q > 0 && a.used >= q
}

// rollLocked сбрасывает расход при смене суток.
func (a *Agent) rollLocked() {
	today := time.Now().Format(dayLayout)
	if a.usedDay == today {
		return
	}
	a.usedDay = today
	a.used = 0
	a.quotaLogged = false
	a.limDirty = true
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
	st := limits.State{Values: a.limits, Used: a.used, Day: a.usedDay}
	a.limDirty = false
	a.limMu.Unlock()

	if err := limits.Save(a.limPath, st); err != nil {
		a.log.Printf("не удалось сохранить настройки: %v", err)
		a.limMu.Lock()
		a.limDirty = true
		a.limMu.Unlock()
	}
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
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

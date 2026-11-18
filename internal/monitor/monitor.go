// Пакет monitor собирает статистику сессий и ресурсов процесса для панели.
package monitor

import (
	"context"
	"io"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/process"
)

const historyLen = 60

type Session struct {
	ID      int64
	Client  string
	KeyID   string
	Host    string
	Port    int
	Started time.Time

	in  atomic.Uint64
	out atomic.Uint64

	inLast  uint64
	outLast uint64
	inRate  float64
	outRate float64

	conn   io.Closer
	cancel context.CancelFunc
}

func (s *Session) AddIn(n int64)  { s.in.Add(uint64(n)) }
func (s *Session) AddOut(n int64) { s.out.Add(uint64(n)) }
func (s *Session) In() uint64     { return s.in.Load() }
func (s *Session) Out() uint64    { return s.out.Load() }
func (s *Session) Close() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
}

type SessionSnapshot struct {
	ID      int64   `json:"id"`
	Client  string  `json:"client"`
	KeyID   string  `json:"key_id"`
	Host    string  `json:"host"`
	Port    int     `json:"port"`
	AgeSec  int64   `json:"age"`
	In      uint64  `json:"in"`
	Out     uint64  `json:"out"`
	InRate  float64 `json:"in_rate"`
	OutRate float64 `json:"out_rate"`
}

type Snapshot struct {
	Sessions []SessionSnapshot `json:"sessions"`
	InRate   float64           `json:"in_rate"`
	OutRate  float64           `json:"out_rate"`
	TotalIn  uint64            `json:"total_in"`
	TotalOut uint64            `json:"total_out"`
	History  []float64         `json:"history"`
}

type Registry struct {
	mu       sync.Mutex
	sessions map[int64]*Session
	nextID   int64

	last    time.Time
	liveIn  uint64
	liveOut uint64
	lifeIn  uint64
	lifeOut uint64
	inRate  float64
	outRate float64
	history []float64
}

func NewRegistry() *Registry {
	return &Registry{
		sessions: make(map[int64]*Session),
		last:     time.Now(),
		history:  make([]float64, 0, historyLen),
	}
}

func (r *Registry) Add(client, keyID, host string, port int, conn io.Closer, cancel context.CancelFunc) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextID++
	s := &Session{
		ID:      r.nextID,
		Client:  client,
		KeyID:   keyID,
		Host:    host,
		Port:    port,
		Started: time.Now(),
		conn:    conn,
		cancel:  cancel,
	}
	r.sessions[s.ID] = s
	return s
}

func (r *Registry) Remove(id int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	if !ok {
		return
	}
	r.lifeIn += s.in.Load()
	r.lifeOut += s.out.Load()
	delete(r.sessions, id)
}

func (r *Registry) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

// Tick пересчитывает скорости. Вызывается раз в секунду.
func (r *Registry) Tick() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	dt := now.Sub(r.last).Seconds()
	if dt <= 0 {
		dt = 1
	}
	r.last = now

	var in, out uint64
	var inRate, outRate float64
	for _, s := range r.sessions {
		ci, co := s.in.Load(), s.out.Load()
		s.inRate = float64(ci-s.inLast) / dt
		s.outRate = float64(co-s.outLast) / dt
		s.inLast, s.outLast = ci, co
		in += ci
		out += co
		inRate += s.inRate
		outRate += s.outRate
	}
	r.liveIn, r.liveOut = in, out
	r.inRate, r.outRate = inRate, outRate

	r.history = append(r.history, inRate+outRate)
	if len(r.history) > historyLen {
		r.history = r.history[len(r.history)-historyLen:]
	}
}

func (r *Registry) Snapshot() Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()

	snaps := make([]SessionSnapshot, 0, len(r.sessions))
	for _, s := range r.sessions {
		snaps = append(snaps, SessionSnapshot{
			ID:      s.ID,
			Client:  s.Client,
			KeyID:   s.KeyID,
			Host:    s.Host,
			Port:    s.Port,
			AgeSec:  int64(time.Since(s.Started).Seconds()),
			In:      s.in.Load(),
			Out:     s.out.Load(),
			InRate:  s.inRate,
			OutRate: s.outRate,
		})
	}
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].ID < snaps[j].ID })

	hist := make([]float64, len(r.history))
	copy(hist, r.history)

	return Snapshot{
		Sessions: snaps,
		InRate:   r.inRate,
		OutRate:  r.outRate,
		TotalIn:  r.lifeIn + r.liveIn,
		TotalOut: r.lifeOut + r.liveOut,
		History:  hist,
	}
}

func (r *Registry) KillAll() {
	r.mu.Lock()
	list := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		list = append(list, s)
	}
	r.mu.Unlock()

	for _, s := range list {
		s.Close()
	}
}

// KillByKey закрывает сессии конкретного пользователя.
func (r *Registry) KillByKey(keyID string) {
	r.mu.Lock()
	list := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		if s.KeyID == keyID {
			list = append(list, s)
		}
	}
	r.mu.Unlock()

	for _, s := range list {
		s.Close()
	}
}

// System — нагрузка, которую создаёт сам процесс, и общая нагрузка ПК.
type System struct {
	mu   sync.RWMutex
	proc *process.Process

	cpuProc float64
	rssMB   float64
	cpuSys  float64
	memSys  float64
}

type SystemSnapshot struct {
	CPUProc float64 `json:"cpu_proc"`
	RSSMB   float64 `json:"rss_mb"`
	CPUSys  float64 `json:"cpu_sys"`
	MemSys  float64 `json:"mem_sys"`
}

func NewSystem() *System {
	p, _ := process.NewProcess(int32(os.Getpid()))
	return &System{proc: p}
}

func (s *System) Sample() {
	var cpuProc, rssMB, cpuSys, memSys float64

	if s.proc != nil {
		if v, err := s.proc.Percent(0); err == nil {
			cpuProc = v
		}
		if mi, err := s.proc.MemoryInfo(); err == nil {
			rssMB = float64(mi.RSS) / 1024 / 1024
		}
	}
	if v, err := cpu.Percent(0, false); err == nil && len(v) > 0 {
		cpuSys = v[0]
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		memSys = vm.UsedPercent
	}

	s.mu.Lock()
	s.cpuProc, s.rssMB, s.cpuSys, s.memSys = cpuProc, rssMB, cpuSys, memSys
	s.mu.Unlock()
}

func (s *System) Snapshot() SystemSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return SystemSnapshot{
		CPUProc: s.cpuProc,
		RSSMB:   s.rssMB,
		CPUSys:  s.cpuSys,
		MemSys:  s.memSys,
	}
}

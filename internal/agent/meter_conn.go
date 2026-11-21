package agent

import (
	"context"
	"net"

	"golang.org/x/time/rate"
)

// meterConn accounts for payload and shares one rate limiter in both directions.
type meterConn struct {
	net.Conn
	onRead  func(int64)
	onWrite func(int64)
	ctx     context.Context
	cancel  context.CancelFunc
	limiter *rate.Limiter
}

// #GPT: propagate cancellation even if it races with the limiter's timer.
func (m *meterConn) wait(n int) error {
	if err := m.ctx.Err(); err != nil {
		return err
	}
	if m.limiter != nil && n > 0 {
		if err := m.limiter.WaitN(m.ctx, n); err != nil {
			return err
		}
	}
	return m.ctx.Err()
}

// #GPT: count bytes received by the agent, then rate-limit forwarding to the site.
func (m *meterConn) Read(p []byte) (int, error) {
	if err := m.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := m.Conn.Read(p)
	if n > 0 {
		m.onRead(int64(n))
		if waitErr := m.wait(n); waitErr != nil {
			// io.Copy forwards nonzero bytes even when Read also returns an error.
			return 0, waitErr
		}
	}
	return n, err
}

// #GPT: honor the same rate limit on downloads and never write after a failed wait.
func (m *meterConn) Write(p []byte) (int, error) {
	if err := m.wait(len(p)); err != nil {
		return 0, err
	}
	n, err := m.Conn.Write(p)
	if n > 0 {
		m.onWrite(int64(n))
	}
	return n, err
}

// #GPT: wake a throttled copy goroutine before closing the network connection.
func (m *meterConn) Close() error {
	m.cancel()
	return m.Conn.Close()
}

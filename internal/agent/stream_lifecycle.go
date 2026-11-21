package agent

import (
	"context"
	"net"
	"time"
)

// agentStream lives from handshake through the last byte. stateMu protects keyID and target.
type agentStream struct {
	ctx    context.Context
	cancel context.CancelFunc
	stream net.Conn
	keyID  string
	target net.Conn
}

// #GPT: keep admission atomic with SetEnabled so a rapid off/on cannot revive an old request.
func (a *Agent) beginStream(stream net.Conn) *agentStream {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if !a.enabled.Load() {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	flow := &agentStream{ctx: ctx, cancel: cancel, stream: stream}
	if a.streams == nil {
		a.streams = make(map[*agentStream]struct{})
	}
	a.streams[flow] = struct{}{}
	return flow
}

// #GPT: reject a target that arrived after the request was cancelled; the caller closes it.
func (a *Agent) attachTarget(flow *agentStream, target net.Conn) bool {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if flow.ctx.Err() != nil {
		return false
	}
	flow.target = target
	_ = flow.stream.SetDeadline(time.Time{})
	return true
}

// #GPT: terminate both directions locally; yamux Close alone leaves its read side open.
func (flow *agentStream) stopLocked() {
	flow.cancel()
	_ = flow.stream.SetDeadline(time.Now())
	if flow.target != nil {
		_ = flow.target.Close()
	}
}

// #GPT: release the tracked request after its handler completes.
func (a *Agent) finishStream(flow *agentStream) {
	a.stateMu.Lock()
	delete(a.streams, flow)
	a.stateMu.Unlock()
	flow.cancel()
}

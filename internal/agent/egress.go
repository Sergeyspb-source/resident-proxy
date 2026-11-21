package agent

import (
	"time"

	"exitnode/internal/egress"
	"exitnode/internal/protocol"
)

func (a *Agent) egressModeLocked() string {
	if a.egressMode == "" {
		return egress.System
	}
	return a.egressMode
}

func (a *Agent) currentEgress() (string, *protocol.EgressObservation) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	return a.egressModeLocked(), a.egressLast
}

// GPT: Persist an explicit owner choice and drop both admitted and pending streams.
func (a *Agent) SetEgressMode(mode string) error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if mode == a.egressModeLocked() {
		return nil
	}
	if err := egress.Save(a.egressPath, mode); err != nil {
		return err
	}
	a.egressMode = mode
	a.egressLast = nil
	a.egressByKey = nil
	for flow := range a.streams {
		flow.stopLocked()
	}
	a.log.Printf("egress mode: %s", mode)
	return nil
}

func (a *Agent) recordEgressLocked(flow *agentStream, host string, port int, route egress.Route, outcome string) {
	if flow.ctx.Err() != nil {
		return
	}
	next := &protocol.EgressObservation{
		Host: host, Port: port, Interface: route.Interface, Kind: route.Kind,
		Outcome: outcome, CheckedAt: time.Now(),
	}
	a.egressLast = next
	if a.egressByKey == nil {
		a.egressByKey = make(map[string]*protocol.EgressObservation)
	}
	a.egressByKey[flow.keyID] = next
}

func (a *Agent) recordEgress(flow *agentStream, host string, port int, route egress.Route, outcome string) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	a.recordEgressLocked(flow, host, port, route, outcome)
}

// GPT: Recheck long-lived pinned sockets and end the stream if the default route changes.
func (a *Agent) watchDirect(flow *agentStream, destination string, host string, port int, initial egress.Route) {
	watch := time.NewTicker(time.Second)
	defer watch.Stop()
	for {
		select {
		case <-flow.ctx.Done():
			return
		case <-watch.C:
			current := egress.Lookup(destination)
			if initial.SamePhysical(current) {
				continue
			}
			a.stateMu.Lock()
			if flow.ctx.Err() == nil {
				a.recordEgressLocked(flow, host, port, current, "blocked")
				flow.stopLocked()
				a.log.Printf("egress route changed for %q:%d", host, port)
			}
			a.stateMu.Unlock()
			return
		}
	}
}

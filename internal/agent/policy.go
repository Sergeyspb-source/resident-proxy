package agent

import (
	"exitnode/internal/limits"
	"exitnode/internal/protocol"
)

// GPT: Expose only the authenticated key's current allowance, even if its quota is exhausted.
func (a *Agent) sendKeyPolicy(conn *protocol.BufConn, flow *agentStream) {
	a.stateMu.Lock()
	idx := a.findKeyLocked(flow.keyID)
	if idx < 0 || flow.ctx.Err() != nil {
		a.stateMu.Unlock()
		return
	}
	key := &a.keys[idx]
	a.rollKeyLocked(key)
	policy := protocol.Policy{
		Version:    1,
		Owner:      a.cfg.Name,
		Domains:    limits.DomainList(key.Limits.Domains),
		DayBytes:   key.Limits.QuotaBytes(),
		DayUsed:    key.Used,
		MonthBytes: key.Limits.QuotaMonthBytes(),
		MonthUsed:  key.UsedMonth,
		RateKBps:   key.Limits.RateKBps,
		EgressMode: a.egressModeLocked(),
	}
	if previous := a.egressByKey[flow.keyID]; previous != nil {
		observation := *previous
		observation.Interface = ""
		policy.LastEgress = &observation
	}
	a.stateMu.Unlock()
	_ = protocol.WriteJSON(conn, policy)
}

package client

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"time"

	"exitnode/internal/protocol"
	"exitnode/internal/secure"
)

// GPT: Fetch policy only after checking both outer TLS and the invitation secret.
func QueryPolicy(ctx context.Context, server, key string) (protocol.Policy, error) {
	var policy protocol.Policy
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	up, err := dialUpstream(ctx, Config{Server: server, Key: key, TLS: true})
	if err != nil {
		return policy, err
	}
	defer up.Close()
	deadline, _ := ctx.Deadline()
	_ = up.SetDeadline(deadline)
	sec, err := secure.Client(ctx, up, key)
	if err != nil {
		return policy, err
	}
	if err := protocol.WriteJSON(sec, protocol.E2EConnect{Action: protocol.E2EPolicy}); err != nil {
		return policy, err
	}
	if err := protocol.ReadJSON(bufio.NewReader(sec), &policy); err != nil {
		return policy, fmt.Errorf("node policy response: %w", err)
	}
	if policy.Version != 1 || policy.Owner == "" || len(policy.Owner) > 128 ||
		policy.DayBytes < 0 || policy.DayUsed < 0 || policy.MonthBytes < 0 || policy.MonthUsed < 0 || policy.RateKBps < 0 {
		return protocol.Policy{}, errors.New("invalid node policy response")
	}
	return policy, nil
}

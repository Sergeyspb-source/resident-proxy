package clientui

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"

	"exitnode/internal/protocol"
	"exitnode/internal/routeprofile"
)

type invitePolicyView struct {
	protocol.Policy
	CheckedAt string `json:"checked_at"`
}

// GPT: Read conditions from the authenticated owner and keep the invitation in process memory.
func (route *systemRoute) inspectInvite(ctx context.Context, invitation *routeprofile.Invitation) string {
	route.mu.Lock()
	route.invite, route.policy = nil, nil
	route.mu.Unlock()
	if invitation == nil {
		return "bad_request"
	}
	settings, err := routeprofile.ReadSettings(routeprofile.Path)
	if err != nil {
		return "profile_failed"
	}
	policy, err := routeprofile.RequestPolicy(ctx, settings, *invitation)
	if err != nil {
		return err.Error()
	}
	route.mu.Lock()
	route.invite = invitation
	route.policy = &invitePolicyView{Policy: policy, CheckedAt: time.Now().Format(time.RFC3339Nano)}
	route.mu.Unlock()
	return ""
}

// GPT: Send a typed selection to the fixed helper; only the helper can change the installed domain.
func (route *systemRoute) selectDomain(ctx context.Context, domain string) string {
	route.mu.Lock()
	invitation, policy := route.invite, route.policy
	route.mu.Unlock()
	if invitation == nil || policy == nil || !routeprofile.ValidDomain(domain) {
		return "domain_not_allowed"
	}
	allowed := false
	for _, name := range policy.Domains {
		if name == domain {
			allowed = true
			break
		}
	}
	if !allowed {
		return "domain_not_allowed"
	}
	selected, err := json.Marshal(routeprofile.Selection{Invitation: *invitation, Domain: domain})
	if err != nil {
		return "profile_failed"
	}
	ctx, cancel := context.WithTimeout(ctx, 18*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/pkexec", "--disable-internal-agent", routeprofile.HelperPath)
	cmd.Stdin = bytes.NewReader(selected)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return ""
	}
	switch code := strings.TrimSpace(string(output)); code {
	case "domain_not_allowed", "invite_mismatch", "policy_unavailable", "stop_before_select":
		return code
	default:
		return "profile_failed"
	}
}

// GPT: Refresh the owner's route observation after an actual connection check.
func (route *systemRoute) refreshInvitationPolicy(ctx context.Context) {
	route.mu.Lock()
	invitation := route.invite
	route.mu.Unlock()
	if invitation == nil {
		return
	}
	settings, err := routeprofile.ReadSettings(routeprofile.Path)
	if err != nil {
		return
	}
	policy, err := routeprofile.RequestPolicy(ctx, settings, *invitation)
	if err != nil {
		return
	}
	route.mu.Lock()
	route.policy = &invitePolicyView{Policy: policy, CheckedAt: time.Now().Format(time.RFC3339Nano)}
	route.mu.Unlock()
}

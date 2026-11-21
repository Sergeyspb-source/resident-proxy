package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type egressControllerFixture struct {
	Controller
	mode string
}

func (c *egressControllerFixture) SetEgressMode(mode string) error {
	c.mode = mode
	return nil
}

func TestEgressChangeRequiresProtectedPost(t *testing.T) {
	ctrl := &egressControllerFixture{mode: "system"}
	h := &handler{ctrl: ctrl}
	req := httptest.NewRequest(http.MethodPost, "/api/egress", strings.NewReader(`{"mode":"direct"}`))
	resp := httptest.NewRecorder()
	h.setEgressMode(resp, req)
	if resp.Code != http.StatusForbidden || ctrl.mode != "system" {
		t.Fatal("unprotected request changed the egress policy")
	}
	req = httptest.NewRequest(http.MethodPost, "/api/egress", strings.NewReader(`{"mode":"direct"}`))
	req.Header.Set("X-Requested-With", "exitnode")
	resp = httptest.NewRecorder()
	h.setEgressMode(resp, req)
	if resp.Code != http.StatusOK || ctrl.mode != "direct" {
		t.Fatalf("protected request failed: %d %s", resp.Code, resp.Body)
	}
}

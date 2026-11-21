package ui

import (
	_ "embed"
	"encoding/json"
	"net/http"
)

// GPT: Apply only a valid explicit owner mode using the existing local POST protection.
func (h *handler) setEgressMode(w http.ResponseWriter, r *http.Request) {
	if !checkPost(w, r) {
		return
	}
	var body struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.ctrl.SetEgressMode(body.Mode); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

//go:embed egress.js
var egressJS []byte

func serveEgressJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(egressJS)
}

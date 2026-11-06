package daemon

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/pastdev/agentcon/internal/bouncer/creds/bitwarden"
)

// Control serves the /_bouncer/ API used by the CLI. Every call requires
// the admin token from the state directory.
func (d *Daemon) Control() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_bouncer/status", func(w http.ResponseWriter, r *http.Request) {
		cfg := d.Config()
		var profiles []string
		for name := range cfg.Profiles {
			profiles = append(profiles, name)
		}
		d.bitwardenMu.Lock()
		pending := append([]string{}, d.bitwardenPending...)
		d.bitwardenMu.Unlock()
		writeJSON(w, map[string]any{
			"config": cfg.Path, "profiles": profiles, "default_profile": cfg.DefaultProfile,
			"sessions": len(d.listSessions()), "pending_approvals": len(d.Approvals.List()),
			"ca": d.CA.CertPath(), "ca_bundle": d.CA.BundlePath(),
			"ready": len(pending) == 0, "bitwarden_pending": pending,
		})
	})
	mux.HandleFunc("POST /_bouncer/credentials/sources/bitwarden/unlock", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Password string `json:"password"`
			Code     string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		bitwarden.SetPrompt(&bitwarden.StaticPrompter{Password: body.Password, Code: body.Code})
		if err := d.creds.Prepare(context.Background(), d.Config().Credentials); err != nil {
			var need *bitwarden.NeedCodeError
			if errors.As(err, &need) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":  "need_code",
					"method": need.Method,
				})
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		d.bitwardenMu.Lock()
		d.bitwardenPending = nil
		d.bitwardenMu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /_bouncer/sessions", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Profile, Label, TTL string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var ttl time.Duration
		if body.TTL != "" {
			var err error
			if ttl, err = time.ParseDuration(body.TTL); err != nil {
				http.Error(w, "ttl: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		rec, err := d.CreateSession(body.Profile, body.Label, ttl)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, NewSession{SessionRecord: *rec, ProxyAddr: d.proxyAddr, SSHAddr: d.sshAddr, Placeholders: d.Placeholders(), SSHHosts: d.SSHHosts()})
	})
	mux.HandleFunc("GET /_bouncer/sessions", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, d.listSessions())
	})
	mux.HandleFunc("DELETE /_bouncer/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !d.EndSession(r.PathValue("id")) {
			http.Error(w, "no such session", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /_bouncer/approvals", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, d.Approvals.List())
	})
	mux.HandleFunc("POST /_bouncer/approvals/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !d.Config().Approvals.CLIEnabled() {
			http.Error(w, "answering approvals via the CLI is disabled (approvals.cli: false)", http.StatusForbidden)
			return
		}
		var body struct{ Allow, Remember bool }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := d.Approvals.Resolve(r.PathValue("id"), body.Allow, body.Remember); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /_bouncer/ca", func(w http.ResponseWriter, r *http.Request) {
		bundle, err := d.CA.BundlePEM()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{
			"cert_pem":        string(d.CA.CertPEM()),
			"bundle_pem":      string(bundle),
			"ssh_known_hosts": d.CA.SSHKnownHostsLine(d.SSHHosts()),
		})
	})
	mux.HandleFunc("POST /_bouncer/reload", func(w http.ResponseWriter, r *http.Request) {
		if err := d.Reload(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("PUT /_bouncer/credentials/provided", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for k, v := range body {
			if k == "" || v == "" {
				http.Error(w, "provided keys and values must be non-empty", http.StatusBadRequest)
				return
			}
		}
		d.creds.SetProvided(body)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("PUT /_bouncer/credentials/sources/env", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for k, v := range body {
			if k == "" || v == "" {
				http.Error(w, "env overlay keys and values must be non-empty", http.StatusBadRequest)
				return
			}
		}
		d.creds.SetEnv(body)
		w.WriteHeader(http.StatusNoContent)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(tok), []byte(d.admin)) != 1 {
			http.Error(w, "agent-bouncer: admin token required", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

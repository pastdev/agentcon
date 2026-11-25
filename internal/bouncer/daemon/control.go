package daemon

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pastdev/agentcon/pkg/bouncer/claims"
	"github.com/pastdev/agentcon/pkg/bouncer/mgmt"
	"github.com/pastdev/agentcon/pkg/bouncer/prompt"
)

// Control serves the /_bouncer/ API used by the CLI. Every call requires
// the admin token from the state directory.
func (d *Daemon) Control() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_bouncer/status", func(w http.ResponseWriter, _ *http.Request) {
		cfg := d.Config()
		var profiles []string
		for name := range cfg.Profiles {
			profiles = append(profiles, name)
		}
		done, startupErr := d.Startup()
		errText := ""
		if startupErr != nil {
			errText = startupErr.Error()
		}
		writeJSON(w, mgmt.Status{
			Config: cfg.Path, Profiles: profiles, DefaultProfile: cfg.DefaultProfile,
			Sessions: len(d.listSessions()), PendingPrompts: len(d.Prompts.List()),
			CA: d.CA.CertPath(), CABundle: d.CA.BundlePath(),
			Ready: done && startupErr == nil, Error: errText,
		})
	})
	mux.HandleFunc("POST /_bouncer/sessions", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID, Profile, Label, TTL string
			Claims                  map[string][]string
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Claims are compared exactly, so input the decoder would change
		// is refused rather than decoded.
		err = checkStrictJSON(raw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		err = json.Unmarshal(raw, &body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		seed, err := claims.FromMap(body.Claims)
		if err != nil {
			http.Error(w, "claims: "+err.Error(), http.StatusBadRequest)
			return
		}
		var ttl time.Duration
		if body.TTL != "" {
			if ttl, err = time.ParseDuration(body.TTL); err != nil {
				http.Error(w, "ttl: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		rec, err := d.CreateSession(body.ID, body.Profile, body.Label, ttl, seed)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, mgmt.NewSession{SessionRecord: rec.wire(), ProxyAddr: d.proxyAddr, SSHAddr: d.sshAddr, Placeholders: d.Placeholders(), SSHHosts: d.SSHHosts(), SignerURL: d.SignerURL(rec.Profile)})
	})
	mux.HandleFunc("GET /_bouncer/sessions", func(w http.ResponseWriter, _ *http.Request) {
		recs := d.listSessions()
		out := make([]mgmt.SessionRecord, 0, len(recs))
		for i := range recs {
			out = append(out, recs[i].wire())
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("DELETE /_bouncer/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !d.EndSession(r.PathValue("id")) {
			http.Error(w, "no such session", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /_bouncer/prompts", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, d.Prompts.List())
	})
	mux.HandleFunc("POST /_bouncer/prompts/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !d.Config().Prompts.CLIEnabled() {
			http.Error(w, errPromptsCLIDisabled, http.StatusForbidden)
			return
		}
		var body struct {
			Allow    bool   `json:"allow"`
			Remember bool   `json:"remember"`
			Value    string `json:"value"`
		}
		err := json.NewDecoder(r.Body).Decode(&body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		err = d.Prompts.Answer(r.PathValue("id"), prompt.Answer{Allow: body.Allow, Remember: body.Remember, Value: body.Value})
		writePromptResult(w, err)
	})
	mux.HandleFunc("DELETE /_bouncer/prompts/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !d.Config().Prompts.CLIEnabled() {
			http.Error(w, errPromptsCLIDisabled, http.StatusForbidden)
			return
		}
		writePromptResult(w, d.Prompts.Decline(r.PathValue("id")))
	})
	mux.HandleFunc("GET /_bouncer/ca", func(w http.ResponseWriter, _ *http.Request) {
		bundle, err := d.CA.BundlePEM()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, mgmt.Trust{
			CertPEM:       string(d.CA.CertPEM()),
			BundlePEM:     string(bundle),
			SSHKnownHosts: d.CA.SSHKnownHostsLine(d.SSHHosts()),
		})
	})
	mux.HandleFunc("POST /_bouncer/reload", func(w http.ResponseWriter, _ *http.Request) {
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
		d.retryStartup()
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
		d.retryStartup()
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
	_ = json.NewEncoder(w).Encode(v)
}

const errPromptsCLIDisabled = "answering prompts through the control API is disabled (prompts.cli: false)"

// writePromptResult maps the result of answering or declining a prompt.
func writePromptResult(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, prompt.ErrNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case err != nil:
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

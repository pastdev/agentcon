package mgmt

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pastdev/agentcon/internal/bouncer/daemon"
	"github.com/pastdev/agentcon/internal/bouncer/running"
)

func TestClientStatusAndApprovals(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_bouncer/status", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer secret" {
			t.Errorf("auth %q", got)
		}
		_ = json.NewEncoder(w).Encode(Status{Ready: true, Config: "/tmp/c.yaml"})
	})
	mux.HandleFunc("POST /_bouncer/approvals/abc", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"allow":true`) {
			t.Errorf("body %s", body)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := New(srv.URL, "secret")
	st, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Ready || st.Config != "/tmp/c.yaml" {
		t.Fatalf("%+v", st)
	}
	err = c.ResolveApproval("abc", true, false)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDialHostJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_bouncer/reload" {
			t.Errorf("path %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	state := t.TempDir()
	addr := strings.TrimPrefix(srv.URL, "http://")
	err := os.WriteFile(filepath.Join(state, "host.json"), []byte(`{"control_addr":"`+addr+`"}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(daemon.AdminTokenPath(state), []byte("tok\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	c, err := Dial(state, filepath.Join(state, "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	err = c.Reload()
	if err != nil {
		t.Fatal(err)
	}
}

func TestDialMissingToken(t *testing.T) {
	state := t.TempDir()
	err := os.WriteFile(filepath.Join(state, "host.json"), []byte(`{"control_addr":"127.0.0.1:1"}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Dial(state, "")
	if err == nil || !strings.Contains(err.Error(), "admin token") {
		t.Fatalf("got %v", err)
	}
}

func TestClientHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no such session", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL, "t")
	err := c.EndSession("missing")
	if err == nil || !strings.Contains(err.Error(), "no such session") {
		t.Fatalf("got %v", err)
	}
}

func TestDialContextUsesRunningRecord(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer from-record" {
			t.Errorf("auth %s", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/_bouncer/reload" {
			t.Errorf("path %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	home := t.TempDir()
	addr := strings.TrimPrefix(srv.URL, "http://")
	err := running.Write(home, running.Record{
		Context:     "foo",
		ControlAddr: addr,
		Token:       "from-record",
		PID:         1,
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := DialContext(home, "foo", "", "")
	if err != nil {
		t.Fatal(err)
	}
	err = c.Reload()
	if err != nil {
		t.Fatal(err)
	}
}

func TestClientTrust(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_bouncer/ca" {
			t.Errorf("path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(Trust{CertPEM: "CERT", BundlePEM: "BUNDLE"})
	}))
	t.Cleanup(srv.Close)
	c := New(srv.URL, "t")
	got, err := c.Trust()
	if err != nil {
		t.Fatal(err)
	}
	if got.CertPEM != "CERT" || got.BundlePEM != "BUNDLE" {
		t.Fatalf("%+v", got)
	}
}

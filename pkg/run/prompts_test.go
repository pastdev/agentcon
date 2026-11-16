package run

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/pastdev/agentcon/pkg/bouncer/mgmt"
	"github.com/pastdev/agentcon/pkg/bouncer/prompt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeStatus serves a scripted sequence of statuses and one pending prompt.
type fakeStatus struct {
	mu       sync.Mutex
	statuses []mgmt.Status
	prompts  []prompt.Pending
}

func (f *fakeStatus) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/_bouncer/status":
		st := f.statuses[0]
		if len(f.statuses) > 1 {
			f.statuses = f.statuses[1:]
		}
		_ = json.NewEncoder(w).Encode(st)
	case "/_bouncer/prompts":
		_ = json.NewEncoder(w).Encode(f.prompts)
	default:
		http.NotFound(w, r)
	}
}

func TestWaitReady(t *testing.T) {
	type testCase struct {
		statuses   []mgmt.Status
		prompts    []prompt.Pending
		timeout    time.Duration
		wantErr    string
		wantStderr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		srv := httptest.NewServer(&fakeStatus{statuses: tc.statuses, prompts: tc.prompts})
		t.Cleanup(srv.Close)
		var stderr bytes.Buffer
		err := waitReady(context.Background(), mgmt.New(srv.URL, "t"), nil, &stderr, tc.timeout)
		if tc.wantErr == "" {
			require.NoError(t, err)
		} else {
			require.ErrorContains(t, err, tc.wantErr)
		}
		assert.Equal(t, tc.wantStderr, stderr.String())
	}
	pending := mgmt.Status{PendingPrompts: 1}
	secret := []prompt.Pending{{ID: "a1", Kind: prompt.KindSecret, Message: "Bitwarden master password"}}

	t.Run("returns when ready", func(t *testing.T) {
		tester(t, testCase{statuses: []mgmt.Status{{}, {Ready: true}}, timeout: time.Minute})
	})
	t.Run("fails with the startup error", func(t *testing.T) {
		tester(t, testCase{statuses: []mgmt.Status{{Error: "bitwarden unlock: prompt declined"}}, timeout: time.Minute,
			wantErr: "bouncer startup: bitwarden unlock: prompt declined"})
	})
	t.Run("lists a prompt once without a terminal", func(t *testing.T) {
		tester(t, testCase{statuses: []mgmt.Status{pending, pending, pending, {Ready: true}}, prompts: secret, timeout: time.Minute,
			wantStderr: "bouncer: pending prompt a1: Bitwarden master password (agentcon bouncer answer a1)\n"})
	})
	t.Run("times out with nothing pending", func(t *testing.T) {
		tester(t, testCase{statuses: []mgmt.Status{{}}, timeout: 300 * time.Millisecond, wantErr: "timed out"})
	})
	t.Run("does not time out while a prompt is pending", func(t *testing.T) {
		statuses := []mgmt.Status{}
		// About 1s of pending polls against a 300ms timeout.
		for range 5 {
			statuses = append(statuses, pending)
		}
		statuses = append(statuses, mgmt.Status{Ready: true})
		tester(t, testCase{statuses: statuses, prompts: secret, timeout: 300 * time.Millisecond,
			wantStderr: "bouncer: pending prompt a1: Bitwarden master password (agentcon bouncer answer a1)\n"})
	})
}

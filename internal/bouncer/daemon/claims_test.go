package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pastdev/agentcon/internal/bouncer/approval"
	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/pkg/bouncer/claims"
	"github.com/pastdev/agentcon/pkg/bouncer/mgmt"
	"github.com/pastdev/agentcon/pkg/bouncer/prompt"
)

// syncBuffer is a bytes.Buffer safe for concurrent log writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.b.Write(p)
	if err != nil {
		return n, fmt.Errorf("audit buffer: %w", err)
	}
	return n, nil
}

// events decodes the audit lines with the given event.
func (s *syncBuffer) events(t *testing.T, event string) []map[string]any {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(s.b.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &m))
		if m["event"] == event {
			delete(m, "level")
			delete(m, "message")
			out = append(out, m)
		}
	}
	return out
}

type claimDaemon struct {
	d      *Daemon
	state  string
	cfg    string
	audit  *syncBuffer
	client *mgmt.Client
}

func newClaimDaemon(t *testing.T, config string) *claimDaemon {
	t.Helper()
	dir := t.TempDir()
	cd := &claimDaemon{state: filepath.Join(dir, "state"), cfg: filepath.Join(dir, "config.yaml"), audit: &syncBuffer{}}
	if config == "" {
		config = "default_profile: p\nprofiles:\n  p: {}\n"
	}
	require.NoError(t, os.WriteFile(cd.cfg, []byte(config), 0o600))
	cd.reopen(t)
	return cd
}

// reopen starts a new daemon on the same state, as after a restart.
func (cd *claimDaemon) reopen(t *testing.T) {
	t.Helper()
	d, err := New(Options{ConfigPath: cd.cfg, StateDir: cd.state, Audit: zerolog.New(cd.audit)})
	require.NoError(t, err)
	cd.d = d
	token, err := os.ReadFile(AdminTokenPath(cd.state))
	require.NoError(t, err)
	srv := httptest.NewServer(d.Control())
	t.Cleanup(srv.Close)
	cd.client = mgmt.New(srv.URL, strings.TrimSpace(string(token)))
}

func TestCreateSessionClaims(t *testing.T) {
	type testCase struct {
		claims     map[string][]string
		wantErr    string
		wantClaims claims.Set
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		cd := newClaimDaemon(t, "")
		var opts []mgmt.SessionOption
		if tc.claims != nil {
			opts = append(opts, mgmt.WithClaims(tc.claims))
		}
		created, err := cd.client.CreateSession(t.Context(), "deadbeef", "", "agentcon", "", opts...)
		list, listErr := cd.client.Sessions(t.Context())
		require.NoError(t, listErr)
		if tc.wantErr != "" {
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			assert.Empty(t, list, "a rejected create made a session")
			assert.Empty(t, cd.audit.events(t, "session_created"))
			assert.Empty(t, cd.audit.events(t, "claim_added"))
			return
		}
		require.NoError(t, err)
		assert.Equal(t, tc.wantClaims, created.Claims)
		require.Len(t, list, 1)
		assert.Equal(t, tc.wantClaims, list[0].Claims)

		wantCreated := map[string]any{"event": "session_created", "session": "deadbeef", "label": "agentcon", "profile": "p", "claims": map[string]any{}}
		for typ, vs := range tc.wantClaims {
			anyVs := make([]any, len(vs))
			for i, v := range vs {
				anyVs[i] = v
			}
			wantCreated["claims"].(map[string]any)[typ] = anyVs
		}
		assert.Equal(t, []map[string]any{wantCreated}, cd.audit.events(t, "session_created"))
		var wantAdded []map[string]any
		for _, c := range tc.wantClaims.List() {
			wantAdded = append(wantAdded, map[string]any{
				"event": "claim_added", "session": "deadbeef", "label": "agentcon",
				"claim_type": c.Type, "claim_value": c.Value, "added_by": "seeded",
			})
		}
		assert.Equal(t, wantAdded, cd.audit.events(t, "claim_added"))
	}
	values := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("v%03d", i)
		}
		return out
	}

	t.Run("no claims is an empty set", func(t *testing.T) {
		tester(t, testCase{wantClaims: claims.Set{}})
	})
	t.Run("seeds claims, deduped and sorted", func(t *testing.T) {
		tester(t, testCase{
			claims:     map[string][]string{"repository": {"g/b", "g/a", "g/b"}, "ticket": {"T-1"}},
			wantClaims: claims.Set{"repository": {"g/a", "g/b"}, "ticket": {"T-1"}},
		})
	})
	t.Run("a partly invalid seed rejects the whole create", func(t *testing.T) {
		tester(t, testCase{claims: map[string][]string{"repository": {"g/a", "bad\r\nvalue"}}, wantErr: "control character"})
	})
	t.Run("an invalid type rejects the create", func(t *testing.T) {
		tester(t, testCase{claims: map[string][]string{"repository": {"g/a"}, "Bad": {"x"}}, wantErr: "lowercase"})
	})
	t.Run("too many values rejects the create", func(t *testing.T) {
		tester(t, testCase{claims: map[string][]string{"repository": values(257)}, wantErr: "claim limit exceeded"})
	})
	t.Run("an empty value list rejects the create", func(t *testing.T) {
		tester(t, testCase{claims: map[string][]string{"repository": {}}, wantErr: "no values"})
	})
}

func TestCreateSessionRawBody(t *testing.T) {
	type testCase struct {
		body       string
		wantStatus int
		wantErr    string
		wantClaims claims.Set
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		cd := newClaimDaemon(t, "")
		token, err := os.ReadFile(AdminTokenPath(cd.state))
		require.NoError(t, err)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/_bouncer/sessions", strings.NewReader(tc.body))
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
		cd.d.Control().ServeHTTP(rec, req)
		require.Equal(t, tc.wantStatus, rec.Code, rec.Body.String())
		list := cd.d.listSessions()
		if tc.wantStatus != http.StatusOK {
			assert.Contains(t, rec.Body.String(), tc.wantErr)
			assert.Empty(t, list, "a rejected create made a session")
			return
		}
		require.Len(t, list, 1)
		assert.Equal(t, tc.wantClaims, list[0].Claims)
	}

	t.Run("a non-object claims field", func(t *testing.T) {
		tester(t, testCase{body: `{"claims":["repository"]}`, wantStatus: http.StatusBadRequest, wantErr: "cannot unmarshal"})
	})
	t.Run("invalid utf8 is not replaced", func(t *testing.T) {
		tester(t, testCase{body: "{\"claims\":{\"t\":[\"a\xffb\"]}}", wantStatus: http.StatusBadRequest, wantErr: "not valid UTF-8"})
	})
	t.Run("an unpaired surrogate is not replaced", func(t *testing.T) {
		tester(t, testCase{body: `{"claims":{"t":["a\ud800b"]}}`, wantStatus: http.StatusBadRequest, wantErr: "unpaired surrogate"})
	})
	t.Run("a duplicate claim type cannot hide an invalid value", func(t *testing.T) {
		tester(t, testCase{body: `{"claims":{"t":["bad\n"],"t":["ok"]}}`, wantStatus: http.StatusBadRequest, wantErr: `repeats the member "t"`})
	})
	t.Run("a duplicate claims key cannot hide invalid claims", func(t *testing.T) {
		tester(t, testCase{body: `{"claims":{"t":["bad\n"]},"claims":{}}`, wantStatus: http.StatusBadRequest, wantErr: `repeats the member "claims"`})
	})
	t.Run("a paired surrogate escape is kept exactly", func(t *testing.T) {
		tester(t, testCase{body: `{"claims":{"t":["a\ud83d\ude00b"]}}`, wantStatus: http.StatusOK, wantClaims: claims.Set{"t": {"a😀b"}}})
	})
}

func TestSessionClaimsLifecycle(t *testing.T) {
	seed := claims.Set{"repository": {"g/a"}}

	t.Run("requests get a copy", func(t *testing.T) {
		cd := newClaimDaemon(t, "")
		rec, err := cd.d.CreateSession("", "", "", 0, seed)
		require.NoError(t, err)
		s, ok := cd.d.Session(rec.Token)
		require.True(t, ok)
		s.Claims["repository"][0] = "evil"
		s.Claims["extra"] = []string{"x"}
		got, ok := cd.d.SessionClaims(&rec.Session)
		require.True(t, ok)
		assert.Equal(t, seed, got)
	})
	t.Run("an operator addition is visible to later requests and audited", func(t *testing.T) {
		cd := newClaimDaemon(t, "")
		rec, err := cd.d.CreateSession("deadbeef", "", "agentcon", 0, seed)
		require.NoError(t, err)
		before, _ := cd.d.Session(rec.Token)
		require.NoError(t, cd.d.AddClaim(&rec.Session, claims.Claim{Type: "repository", Value: "g/b"}, "scope", "a1b2c3"))
		require.NoError(t, cd.d.AddClaim(&rec.Session, claims.Claim{Type: "repository", Value: "g/b"}, "scope", "d4e5f6"), "a duplicate is a no-op")
		after, _ := cd.d.Session(rec.Token)
		assert.Equal(t, seed, before.Claims, "an earlier request's copy changed")
		assert.Equal(t, claims.Set{"repository": {"g/a", "g/b"}}, after.Claims)
		assert.Equal(t, []map[string]any{
			{"event": "claim_added", "session": "deadbeef", "label": "agentcon", "claim_type": "repository", "claim_value": "g/a", "added_by": "seeded"},
			{
				"event": "claim_added", "session": "deadbeef", "label": "agentcon", "claim_type": "repository", "claim_value": "g/b",
				"added_by": "operator", "filter": "scope", "prompt": "a1b2c3",
			},
		}, cd.audit.events(t, "claim_added"))
	})
	t.Run("a claim that fails to save is not granted", func(t *testing.T) {
		cd := newClaimDaemon(t, "")
		rec, err := cd.d.CreateSession("deadbeef", "", "agentcon", 0, seed)
		require.NoError(t, err)
		// A directory where the temp file goes makes every save fail.
		tmp := filepath.Join(cd.state, "sessions.json.tmp")
		require.NoError(t, os.Mkdir(tmp, 0o700))
		err = cd.d.AddClaim(&rec.Session, claims.Claim{Type: "repository", Value: "g/b"}, "scope", "a1b2c3")
		require.ErrorContains(t, err, "save claim")
		got, _ := cd.d.SessionClaims(&rec.Session)
		assert.Equal(t, seed, got, "an unsaved claim was granted")
		assert.Len(t, cd.audit.events(t, "claim_added"), 1, "only the seeded claim is audited")

		require.NoError(t, os.Remove(tmp))
		require.NoError(t, cd.d.AddClaim(&rec.Session, claims.Claim{Type: "repository", Value: "g/b"}, "scope", "d4e5f6"))
		cd.reopen(t)
		got, _ = cd.d.SessionClaims(&rec.Session)
		assert.Equal(t, claims.Set{"repository": {"g/a", "g/b"}}, got)
	})
	t.Run("an approval whose claim fails to save allows once", func(t *testing.T) {
		cd := newClaimDaemon(t, "")
		rec, err := cd.d.CreateSession("deadbeef", "", "", 0, seed)
		require.NoError(t, err)
		require.NoError(t, os.Mkdir(filepath.Join(cd.state, "sessions.json.tmp"), 0o700))
		s, _ := cd.d.Session(rec.Token)
		events, cancel := cd.d.Prompts.Subscribe()
		defer cancel()
		done := make(chan bool, 1)
		go func() {
			ok, _ := cd.d.env.Claims.RequestClaim(context.Background(), chain.ClaimRequest{
				Session: s, Filter: "scope", Prompt: "?", Claim: claims.Claim{Type: "repository", Value: "g/b"},
			})
			done <- ok
		}()
		ev := <-events
		require.NoError(t, cd.d.Prompts.Answer(ev.Pending.ID, prompt.Answer{Allow: true, Remember: true}))
		assert.True(t, <-done, "the operator allowed this request")
		got, _ := cd.d.SessionClaims(&rec.Session)
		assert.Equal(t, seed, got)
	})
	t.Run("an addition over the limit fails", func(t *testing.T) {
		cd := newClaimDaemon(t, "")
		full := claims.Set{}
		for i := range claims.MaxTypes {
			full[fmt.Sprintf("t%02d", i)] = []string{"v"}
		}
		rec, err := cd.d.CreateSession("", "", "", 0, full)
		require.NoError(t, err)
		err = cd.d.AddClaim(&rec.Session, claims.Claim{Type: "another", Value: "v"}, "f", "p")
		require.ErrorIs(t, err, claims.ErrLimit)
	})
	t.Run("ending the session discards its claims", func(t *testing.T) {
		cd := newClaimDaemon(t, "")
		rec, err := cd.d.CreateSession("deadbeef", "", "", 0, seed)
		require.NoError(t, err)
		require.True(t, cd.d.EndSession(rec.ID))
		_, ok := cd.d.SessionClaims(&rec.Session)
		assert.False(t, ok)
		err = cd.d.AddClaim(&rec.Session, claims.Claim{Type: "repository", Value: "g/b"}, "f", "p")
		require.ErrorIs(t, err, approval.ErrSessionGone)
		again, err := cd.d.CreateSession("deadbeef", "", "", 0, nil)
		require.NoError(t, err)
		assert.Equal(t, claims.Set{}, again.Claims, "a new session with the same id inherited claims")
	})
	t.Run("expiry discards its claims", func(t *testing.T) {
		cd := newClaimDaemon(t, "")
		rec, err := cd.d.CreateSession("deadbeef", "", "", 20*time.Millisecond, seed)
		require.NoError(t, err)
		time.Sleep(40 * time.Millisecond)
		_, ok := cd.d.SessionClaims(&rec.Session)
		assert.False(t, ok)
		err = cd.d.AddClaim(&rec.Session, claims.Claim{Type: "repository", Value: "g/b"}, "f", "p")
		require.ErrorIs(t, err, approval.ErrSessionGone)
		again, err := cd.d.CreateSession("deadbeef", "", "", 0, nil)
		require.NoError(t, err)
		assert.Equal(t, claims.Set{}, again.Claims)
	})
	t.Run("claims survive a restart, including operator additions", func(t *testing.T) {
		cd := newClaimDaemon(t, "")
		rec, err := cd.d.CreateSession("deadbeef", "", "", 0, seed)
		require.NoError(t, err)
		require.NoError(t, cd.d.AddClaim(&rec.Session, claims.Claim{Type: "repository", Value: "g/b"}, "f", "p"))
		cd.reopen(t)
		s, ok := cd.d.Session(rec.Token)
		require.True(t, ok)
		assert.Equal(t, claims.Set{"repository": {"g/a", "g/b"}}, s.Claims)
		assert.Equal(t, rec.Instance, s.Instance, "the instance changed across a restart")
		require.NoError(t, cd.d.AddClaim(&rec.Session, claims.Claim{Type: "repository", Value: "g/c"}, "f", "p"))
	})
	t.Run("a saved session from before claims loads with none", func(t *testing.T) {
		cd := newClaimDaemon(t, "")
		old := `[{"id":"deadbeef","label":"old","profile":"p","token":"tok","created":"2026-01-01T00:00:00Z"}]`
		require.NoError(t, os.WriteFile(filepath.Join(cd.state, "sessions.json"), []byte(old), 0o600))
		cd.reopen(t)
		s, ok := cd.d.Session("tok")
		require.True(t, ok)
		assert.Equal(t, claims.Set{}, s.Claims)
		assert.NotEmpty(t, s.Instance, "an old record got no instance")
	})
	t.Run("a saved session with invalid claims is dropped", func(t *testing.T) {
		cd := newClaimDaemon(t, "")
		bad := `[{"id":"deadbeef","label":"bad","profile":"p","token":"tok","created":"2026-01-01T00:00:00Z","claims":{"Repo":["x"]}},
			{"id":"cafef00d","label":"good","profile":"p","token":"tok2","created":"2026-01-01T00:00:00Z","claims":{"repo":["b","a"]}}]`
		require.NoError(t, os.WriteFile(filepath.Join(cd.state, "sessions.json"), []byte(bad), 0o600))
		cd.reopen(t)
		_, ok := cd.d.Session("tok")
		assert.False(t, ok)
		s, ok := cd.d.Session("tok2")
		require.True(t, ok)
		assert.Equal(t, claims.Set{"repo": {"a", "b"}}, s.Claims)
	})
	t.Run("the anonymous session has no claims and never gains one", func(t *testing.T) {
		cd := newClaimDaemon(t, "default_profile: p\nanonymous_profile: p\nprofiles:\n  p: {}\n")
		s, ok := cd.d.Session("")
		require.True(t, ok)
		assert.Equal(t, claims.Set{}, s.Claims)
		events, cancel := cd.d.Prompts.Subscribe()
		defer cancel()
		done := make(chan bool, 1)
		go func() {
			ok, _ := cd.d.env.Claims.RequestClaim(context.Background(), chain.ClaimRequest{
				Session: s, Filter: "f", Prompt: "?", Claim: claims.Claim{Type: "repository", Value: "g/a"},
			})
			done <- ok
		}()
		ev := <-events
		require.NoError(t, cd.d.Prompts.Answer(ev.Pending.ID, prompt.Answer{Allow: true, Remember: true}))
		assert.True(t, <-done)
		s, _ = cd.d.Session("")
		assert.Equal(t, claims.Set{}, s.Claims)
		assert.Empty(t, cd.audit.events(t, "claim_added"))
	})
}

func TestClaimPromptsAndSessionEnd(t *testing.T) {
	request := func(cd *claimDaemon, s *chain.Session) <-chan bool {
		done := make(chan bool, 1)
		go func() {
			ok, _ := cd.d.env.Claims.RequestClaim(context.Background(), chain.ClaimRequest{
				Session: s, Filter: "scope", Prompt: "?", Claim: claims.Claim{Type: "repository", Value: "g/b"},
			})
			done <- ok
		}()
		return done
	}
	pending := func(t *testing.T, cd *claimDaemon, n int) []prompt.Pending {
		t.Helper()
		require.Eventually(t, func() bool { return len(cd.d.Prompts.List()) == n }, time.Second, 5*time.Millisecond)
		return cd.d.Prompts.List()
	}

	t.Run("ending a session withdraws its claim prompts and its id starts clean", func(t *testing.T) {
		cd := newClaimDaemon(t, "")
		rec, err := cd.d.CreateSession("deadbeef", "", "", 0, nil)
		require.NoError(t, err)
		s, _ := cd.d.Session(rec.Token)
		done := request(cd, s)
		pending(t, cd, 1)
		require.True(t, cd.d.EndSession("deadbeef"))
		assert.False(t, <-done)
		pending(t, cd, 0)
		again, err := cd.d.CreateSession("deadbeef", "", "", 0, nil)
		require.NoError(t, err)
		assert.NotEqual(t, rec.Instance, again.Instance)
		assert.Equal(t, claims.Set{}, again.Claims)
	})
	t.Run("an approval after expiry never reaches a session that reuses the id", func(t *testing.T) {
		cd := newClaimDaemon(t, "")
		rec, err := cd.d.CreateSession("deadbeef", "", "", 50*time.Millisecond, nil)
		require.NoError(t, err)
		s, _ := cd.d.Session(rec.Token)
		done := request(cd, s)
		old := pending(t, cd, 1)[0]
		time.Sleep(80 * time.Millisecond)
		again, err := cd.d.CreateSession("deadbeef", "", "", 0, nil)
		require.NoError(t, err)

		require.NoError(t, cd.d.Prompts.Answer(old.ID, prompt.Answer{Allow: true, Remember: true}))
		assert.False(t, <-done, "an approval for an expired session went through")
		got, ok := cd.d.SessionClaims(&again.Session)
		require.True(t, ok)
		assert.Equal(t, claims.Set{}, got)
		assert.Empty(t, cd.audit.events(t, "claim_added"))
	})
	t.Run("the same request from a reused id gets its own prompt", func(t *testing.T) {
		cd := newClaimDaemon(t, "")
		rec, err := cd.d.CreateSession("deadbeef", "", "", 50*time.Millisecond, nil)
		require.NoError(t, err)
		s, _ := cd.d.Session(rec.Token)
		first := request(cd, s)
		pending(t, cd, 1)
		time.Sleep(80 * time.Millisecond)
		again, err := cd.d.CreateSession("deadbeef", "", "", 0, nil)
		require.NoError(t, err)
		s2, _ := cd.d.Session(again.Token)
		second := request(cd, s2)
		list := pending(t, cd, 2)
		for _, p := range list {
			require.NoError(t, cd.d.Prompts.Answer(p.ID, prompt.Answer{}))
		}
		assert.False(t, <-first)
		assert.False(t, <-second)
	})
}

func TestRequestClaimThroughDaemon(t *testing.T) {
	cd := newClaimDaemon(t, "")
	ctx := t.Context()
	created, err := cd.client.CreateSession(ctx, "deadbeef", "", "agentcon", "", mgmt.WithClaims(map[string][]string{"repository": {"g/a"}}))
	require.NoError(t, err)
	sess, ok := cd.d.Session(created.Token)
	require.True(t, ok)

	done := make(chan bool, 1)
	go func() {
		ok, _ := cd.d.env.Claims.RequestClaim(context.Background(), chain.ClaimRequest{
			Session: sess, Filter: "scope", Prompt: "create issues in g/b?",
			Claim: claims.Claim{Type: "repository", Value: "g/b"}, Request: "POST x",
		})
		done <- ok
	}()
	var pending []prompt.Pending
	require.Eventually(t, func() bool {
		pending, err = cd.client.Prompts(ctx)
		return err == nil && len(pending) == 1
	}, time.Second, 5*time.Millisecond)
	p := pending[0]
	assert.Equal(t, prompt.KindClaim, p.Kind)
	assert.Equal(t, &claims.Claim{Type: "repository", Value: "g/b"}, p.Claim)
	assert.Equal(t, claims.Set{"repository": {"g/a"}}, p.SessionClaims)

	err = cd.client.AnswerPrompt(ctx, p.ID, prompt.Answer{Remember: true})
	require.Error(t, err, "deny for session is not a claim answer")
	err = cd.client.AnswerPrompt(ctx, p.ID, prompt.Answer{Allow: true, Remember: true})
	require.NoError(t, err)
	assert.True(t, <-done)

	list, err := cd.client.Sessions(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, claims.Set{"repository": {"g/a", "g/b"}}, list[0].Claims)
}

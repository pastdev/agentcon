package jsfilter

import (
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/pkg/bouncer/claims"
)

type claimRequester struct {
	calls  []chain.ClaimRequest
	answer bool
	err    error
}

func (c *claimRequester) RequestClaim(_ context.Context, r chain.ClaimRequest) (bool, error) {
	c.calls = append(c.calls, r)
	return c.answer, c.err
}

func TestSessionClaims(t *testing.T) {
	type testCase struct {
		src      string
		claims   claims.Set
		wantBody string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		f := load(t, tc.src, Options{})
		r := req(t, "GET", "https://x/", nil)
		r.Session = &chain.Session{ID: "s1", Claims: tc.claims}
		var before claims.Set
		if tc.claims != nil {
			before = tc.claims.Clone()
		}
		resp, err := chain.Build([]chain.Filter{f}, upstream("ok"))(r)
		require.NoError(t, err)
		require.Nil(t, resp.Denial, "%+v", resp.Denial)
		b, err := io.ReadAll(resp.Body.Reader())
		require.NoError(t, err)
		assert.JSONEq(t, tc.wantBody, string(b))
		assert.Equal(t, before, r.Session.Claims, "the filter changed the session's claims")
	}

	t.Run("filters read claims", func(t *testing.T) {
		tester(t, testCase{
			src: `
import { defineFilter, respond } from "bouncer";
export default defineFilter({
  onRequest(req) { return respond(200, req.session.claims); },
});`,
			claims:   claims.Set{"repository": {"a", "b"}},
			wantBody: `{"repository":["a","b"]}`,
		})
	})
	t.Run("a session without claims shows {}", func(t *testing.T) {
		tester(t, testCase{
			src: `
import { defineFilter, respond } from "bouncer";
export default defineFilter({
  onRequest(req) { return respond(200, req.session.claims); },
});`,
			wantBody: `{}`,
		})
	})
	t.Run("mutation attempts have no effect", func(t *testing.T) {
		tester(t, testCase{
			src: `
import { defineFilter, respond } from "bouncer";
export default defineFilter({
  onRequest(req) {
    const c: any = req.session.claims;
    const tries: Record<string, () => void> = {
      assign: () => { c.repository = ["evil"]; },
      add: () => { c.extra = ["evil"]; },
      remove: () => { delete c.repository; },
      push: () => { c.repository.push("evil"); },
      index: () => { c.repository[0] = "evil"; },
      replace: () => { (req.session as any).claims = { evil: ["x"] }; },
      define: () => { Object.defineProperty(c, "x", { value: 1 }); },
    };
    // Each attempt either throws or is ignored; neither changes anything.
    for (const k of Object.keys(tries)) {
      try { tries[k](); } catch (e) {}
    }
    return respond(200, { claims: req.session.claims, same: req.session.claims === c,
      frozen: Object.isFrozen(c) && Object.isFrozen(c.repository) });
  },
});`,
			claims:   claims.Set{"repository": {"a"}},
			wantBody: `{"claims":{"repository":["a"]},"same":true,"frozen":true}`,
		})
	})
	t.Run("replacing Object.freeze does not unfreeze claims", func(t *testing.T) {
		tester(t, testCase{
			src: `
import { defineFilter, respond } from "bouncer";
(Object as any).freeze = (o: any) => o;
export default defineFilter({
  onRequest(req) {
    const c: any = req.session.claims;
    try { c.repository.push("evil"); } catch (e) {}
    return respond(200, { claims: c, frozen: Object.isFrozen(c.repository) });
  },
});`,
			claims:   claims.Set{"repository": {"a"}},
			wantBody: `{"claims":{"repository":["a"]},"frozen":true}`,
		})
	})
}

func TestRequestClaim(t *testing.T) {
	type testCase struct {
		call      string
		requester *claimRequester
		wantBody  string
		wantCalls []chain.ClaimRequest
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		src := fmt.Sprintf(`
import { defineFilter, respond, requestClaim } from "bouncer";
export default defineFilter({
  async onRequest(req) {
    try {
      return respond(200, { ok: await %s });
    } catch (e) {
      return respond(200, { threw: String((e as any).message ?? e) });
    }
  },
});`, tc.call)
		env := &chain.Env{}
		if tc.requester != nil {
			env.Claims = tc.requester
		}
		f := load(t, src, Options{Env: env})
		r := req(t, "POST", "https://gitlab.example.com/api/v4/projects/g%2Fp/issues", nil)
		r.Session = &chain.Session{ID: "s1", Label: "agent", Claims: claims.Set{}}
		resp, err := chain.Build([]chain.Filter{f}, upstream("ok"))(r)
		require.NoError(t, err)
		b, err := io.ReadAll(resp.Body.Reader())
		require.NoError(t, err)
		assert.JSONEq(t, tc.wantBody, string(b))
		if tc.requester != nil {
			for i := range tc.requester.calls {
				tc.requester.calls[i].Session = nil
			}
			assert.Equal(t, tc.wantCalls, tc.requester.calls)
		}
	}
	call := chain.ClaimRequest{
		Filter: "f", Prompt: "create issues in g/p?",
		Claim:   claims.Claim{Type: "repository", Value: "gitlab.example.com/g/p"},
		Request: "POST gitlab.example.com/api/v4/projects/g%2Fp/issues",
	}

	t.Run("resolves the operator's answer", func(t *testing.T) {
		tester(t, testCase{
			call:      `requestClaim("repository", "gitlab.example.com/g/p", "create issues in g/p?")`,
			requester: &claimRequester{answer: true},
			wantBody:  `{"ok":true}`,
			wantCalls: []chain.ClaimRequest{call},
		})
	})
	t.Run("resolves a denial", func(t *testing.T) {
		tester(t, testCase{
			call:      `requestClaim("repository", "gitlab.example.com/g/p", "create issues in g/p?", { timeout: "1s" })`,
			requester: &claimRequester{},
			wantBody:  `{"ok":false}`,
			wantCalls: []chain.ClaimRequest{call},
		})
	})
	t.Run("an answer with an error still resolves", func(t *testing.T) {
		tester(t, testCase{
			call:      `requestClaim("repository", "gitlab.example.com/g/p", "create issues in g/p?")`,
			requester: &claimRequester{answer: true, err: fmt.Errorf("allowed once, not added")},
			wantBody:  `{"ok":true}`,
			wantCalls: []chain.ClaimRequest{call},
		})
	})
	t.Run("invalid type throws without asking", func(t *testing.T) {
		tester(t, testCase{
			call:      `requestClaim("Repository", "x", "?")`,
			requester: &claimRequester{answer: true},
			wantBody:  `{"threw":"requestClaim: claim type \"Repository\" must start with a lowercase letter"}`,
		})
	})
	t.Run("invalid value throws without asking", func(t *testing.T) {
		tester(t, testCase{
			call:      `requestClaim("repository", "a\nb", "?")`,
			requester: &claimRequester{answer: true},
			wantBody:  `{"threw":"requestClaim: claim repository: claim value contains a control character"}`,
		})
	})
	t.Run("oversized value throws without asking", func(t *testing.T) {
		tester(t, testCase{
			call:      `requestClaim("repository", "x".repeat(1025), "?")`,
			requester: &claimRequester{answer: true},
			wantBody:  `{"threw":"requestClaim: claim repository: claim value is longer than 1024 bytes"}`,
		})
	})
	t.Run("non-string arguments throw", func(t *testing.T) {
		tester(t, testCase{
			call:      `requestClaim("repository", 42 as any, "?")`,
			requester: &claimRequester{answer: true},
			wantBody:  `{"threw":"requestClaim(type, value, prompt) requires string type and value"}`,
		})
	})
	t.Run("a rejected request throws", func(t *testing.T) {
		tester(t, testCase{
			call:      `requestClaim("repository", "gitlab.example.com/g/p", "create issues in g/p?")`,
			requester: &claimRequester{err: fmt.Errorf("%w: %w", chain.ErrClaimRejected, claims.ErrLimit)},
			wantBody:  `{"threw":"requestClaim: claim request rejected: claim limit exceeded"}`,
			wantCalls: []chain.ClaimRequest{call},
		})
	})
	t.Run("no requester resolves false", func(t *testing.T) {
		tester(t, testCase{
			call:     `requestClaim("repository", "gitlab.example.com/g/p", "?")`,
			wantBody: `{"ok":false}`,
		})
	})
}

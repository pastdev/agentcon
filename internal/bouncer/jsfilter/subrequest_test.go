package jsfilter

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pastdev/agentcon/internal/bouncer/chain"
)

// trackedBody records whether it was closed.
type trackedBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *trackedBody) Close() error {
	b.closed.Store(true)
	return nil
}

// fakeSub is a SubrequestFunc that records what it was asked and answers
// with resp or err.
type fakeSub struct {
	parent *chain.Request
	filter string
	caller chain.SubrequestCaller
	spec   chain.SubrequestSpec
	resp   func() *chain.Response
	err    error
	delay  time.Duration
}

func (f *fakeSub) do(parent *chain.Request, caller chain.SubrequestCaller, spec chain.SubrequestSpec) (*chain.Response, *url.URL, error) {
	f.parent, f.filter, f.caller, f.spec = parent, caller.Filter, caller, spec
	time.Sleep(f.delay)
	if f.err != nil {
		return nil, nil, f.err
	}
	u, _ := url.Parse(spec.URL)
	if f.resp == nil {
		return &chain.Response{Status: 200, Header: http.Header{}, Body: chain.BytesBody([]byte(`{"ok":true}`))}, u, nil
	}
	return f.resp(), u, nil
}

func TestSubrequest(t *testing.T) {
	type testCase struct {
		src     string
		sub     *fakeSub
		env     *chain.Env
		req     *chain.Request
		timeout time.Duration
		// deny is the expected denial reason, "" for an allowed request.
		deny    string
		wantErr string
		body    string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		env := tc.env
		if env == nil {
			env = &chain.Env{}
		}
		if tc.sub != nil {
			env.Subrequest = tc.sub.do
		}
		f := load(t, tc.src, Options{Env: env, Timeout: tc.timeout})
		r := tc.req
		if r == nil {
			r = req(t, "POST", "https://github.com/o/r.git/git-receive-pack", nil)
		}
		resp, err := f.Handle(r, upstream("upstream"))
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		if tc.deny != "" {
			require.NotNil(t, resp.Denial, "expected a denial")
			assert.Contains(t, resp.Denial.Reason, tc.deny)
		} else {
			assert.Nil(t, resp.Denial)
		}
		if tc.body != "" {
			b, err := resp.Body.ReadAll()
			require.NoError(t, err)
			assert.Equal(t, tc.body, string(b))
		}
	}

	t.Run("resolves with the response", func(t *testing.T) {
		sub := &fakeSub{}
		tester(t, testCase{
			src: `import { defineFilter, deny, subrequest } from "bouncer";
export default defineFilter({
  async onRequest(req, next) {
    const r = await subrequest({ url: "https://api.github.com/repos/o/r/rules/branches/main", headers: { Accept: "application/json" } });
    const j = await r.body.json();
    if (r.status !== 200 || !j.ok || r.denied !== null || r.url !== "https://api.github.com/repos/o/r/rules/branches/main") return deny("bad response");
    return next(req);
  },
});`,
			sub: sub,
		})
		assert.Equal(t, "f", sub.filter)
		assert.Equal(t, "https://api.github.com/repos/o/r/rules/branches/main", sub.spec.URL)
		assert.Equal(t, "application/json", sub.spec.Header.Get("Accept"))
		assert.Empty(t, sub.spec.Method, "the router defaults the method")
		assert.False(t, sub.spec.Manual)
		assert.Equal(t, "POST", sub.parent.Method)
	})
	t.Run("passes method, body, redirect, and timeout", func(t *testing.T) {
		sub := &fakeSub{}
		tester(t, testCase{
			src: `import { defineFilter, subrequest } from "bouncer";
export default defineFilter({
  async onRequest(req, next) {
    await subrequest({ url: "https://x/y", method: "POST", body: { a: 1 }, redirect: "manual", timeout: "3s" });
    return next(req);
  },
});`,
			sub: sub,
		})
		assert.Equal(t, "POST", sub.spec.Method)
		assert.JSONEq(t, `{"a":1}`, string(sub.spec.Body))
		assert.Equal(t, "application/json", sub.spec.Header.Get("Content-Type"))
		assert.True(t, sub.spec.Manual)
		assert.Equal(t, 3*time.Second, sub.spec.Timeout)
	})
	t.Run("a string body keeps its content type", func(t *testing.T) {
		sub := &fakeSub{}
		tester(t, testCase{
			src: `import { defineFilter, subrequest } from "bouncer";
export default defineFilter({
  async onRequest(req, next) {
    await subrequest({ url: "https://x/y", method: "POST", body: "a=1", headers: { "Content-Type": "text/plain" } });
    return next(req);
  },
});`,
			sub: sub,
		})
		assert.Equal(t, "a=1", string(sub.spec.Body))
		assert.Equal(t, "text/plain", sub.spec.Header.Get("Content-Type"))
	})
	t.Run("a denied subrequest resolves with denied set", func(t *testing.T) {
		tester(t, testCase{
			src: `import { defineFilter, deny, subrequest } from "bouncer";
export default defineFilter({
  async onRequest(req, next) {
    const r = await subrequest({ url: "https://x/y" });
    if (r.denied) return deny("lookup denied by " + r.denied.by + ": " + r.denied.reason);
    return next(req);
  },
});`,
			sub:  &fakeSub{resp: func() *chain.Response { return chain.Deny("rules", "no rule allows it") }},
			deny: "lookup denied by rules: no rule allows it",
		})
	})
	t.Run("an uncaught rejection fails the request", func(t *testing.T) {
		tester(t, testCase{
			src: `import { defineFilter, subrequest } from "bouncer";
export default defineFilter({
  async onRequest(req, next) {
    await subrequest({ url: "https://x/y" });
    return next(req);
  },
});`,
			sub:     &fakeSub{err: errors.New("subrequest: depth 5 exceeds limit 4")},
			wantErr: "subrequest: depth 5 exceeds limit 4",
		})
	})
	t.Run("a caught rejection can deny", func(t *testing.T) {
		tester(t, testCase{
			src: `import { defineFilter, deny, subrequest } from "bouncer";
export default defineFilter({
  async onRequest(req, next) {
    try {
      await subrequest({ url: "https://x/y" });
    } catch (e) {
      return deny("lookup failed: " + e.message);
    }
    return next(req);
  },
});`,
			sub:  &fakeSub{err: errors.New("subrequest: upstream: connection refused")},
			deny: "lookup failed: subrequest: upstream: connection refused",
		})
	})
	t.Run("a malformed init throws", func(t *testing.T) {
		for _, init := range []string{`undefined`, `{}`, `{ url: "" }`, `{ url: 1 }`, `{ url: "https://x", redirect: "error" }`, `{ url: "https://x", timeout: 0 }`, `{ url: "https://x", headers: "x" }`} {
			tester(t, testCase{
				src: `import { defineFilter, subrequest } from "bouncer";
export default defineFilter({
  async onRequest(req, next) {
    await subrequest(` + init + `);
    return next(req);
  },
});`,
				sub:     &fakeSub{},
				wantErr: "subrequest",
			})
		}
	})
	t.Run("throws when not configured", func(t *testing.T) {
		tester(t, testCase{
			src: `import { defineFilter, subrequest } from "bouncer";
export default defineFilter({
  async onRequest(req, next) {
    await subrequest({ url: "https://x/y" });
    return next(req);
  },
});`,
			wantErr: "subrequest() is not configured",
		})
	})
	t.Run("throws at module top level", func(t *testing.T) {
		p := writeFilter(t, t.TempDir(), "top.ts", `import { defineFilter, subrequest } from "bouncer";
subrequest({ url: "https://x/y" });
export default defineFilter({ onRequest(req, next) { return next(req); } });`)
		_, err := Load(Options{Path: p, Env: &chain.Env{Subrequest: (&fakeSub{}).do}})
		require.ErrorContains(t, err, "subrequest() can only be called while handling a request")
	})
	t.Run("works from onSSH", func(t *testing.T) {
		sub := &fakeSub{}
		r := &chain.Request{Ctx: req(t, "GET", "https://x/", nil).Ctx, Transport: chain.TransportSSH, Session: &chain.Session{ID: "s1"},
			SSH: &chain.SSHInfo{Host: "github.com", User: "git", Kind: "git", Command: "git-receive-pack 'o/r.git'"}}
		tester(t, testCase{
			src: `import { defineFilter, deny, subrequest } from "bouncer";
export default defineFilter({
  async onSSH(req, next) {
    const r = await subrequest({ url: "https://api.github.com/repos/" + req.git.repo });
    return r.status === 200 ? next(req) : deny("lookup");
  },
});`,
			sub: sub,
			req: r,
		})
		assert.Equal(t, "https://api.github.com/repos/o/r", sub.spec.URL)
		assert.Equal(t, chain.TransportSSH, sub.parent.Transport)
	})
	t.Run("works from onResponse", func(t *testing.T) {
		sub := &fakeSub{}
		tester(t, testCase{
			src: `import { defineFilter, subrequest } from "bouncer";
export default defineFilter({
  async onResponse(res, req) {
    await subrequest({ url: "https://x/after" });
  },
});`,
			sub:  sub,
			body: "upstream",
		})
		assert.Equal(t, "https://x/after", sub.spec.URL)
	})
	t.Run("time waiting on a subrequest does not count toward the CPU budget", func(t *testing.T) {
		tester(t, testCase{
			src: `import { defineFilter, subrequest } from "bouncer";
export default defineFilter({
  async onRequest(req, next) {
    await subrequest({ url: "https://x/y" });
    return next(req);
  },
});`,
			sub:     &fakeSub{delay: 300 * time.Millisecond},
			timeout: 100 * time.Millisecond,
		})
	})
	t.Run("unread bodies are closed when the run ends", func(t *testing.T) {
		body := &trackedBody{Reader: strings.NewReader("unread")}
		tester(t, testCase{
			src: `import { defineFilter, subrequest } from "bouncer";
export default defineFilter({
  async onRequest(req, next) {
    await subrequest({ url: "https://x/y" });
    return next(req);
  },
});`,
			sub: &fakeSub{resp: func() *chain.Response {
				return &chain.Response{Status: 200, Header: http.Header{}, Body: chain.NewBody(body)}
			}},
		})
		assert.True(t, body.closed.Load())
	})
	t.Run("a returned subrequest response keeps its body open", func(t *testing.T) {
		body := &trackedBody{Reader: strings.NewReader("relayed")}
		tester(t, testCase{
			src: `import { defineFilter, subrequest } from "bouncer";
export default defineFilter({
  async onRequest(req, next) {
    return await subrequest({ url: "https://x/y" });
  },
});`,
			sub: &fakeSub{resp: func() *chain.Response {
				return &chain.Response{Status: 200, Header: http.Header{}, Body: chain.NewBody(body)}
			}},
			body: "relayed",
		})
		assert.False(t, body.closed.Load())
	})
}

func TestRequestSubrequestField(t *testing.T) {
	src := `import { defineFilter, deny } from "bouncer";
export default defineFilter({
  onRequest(req, next) {
    "use strict";
    const s = req.subrequest;
    if (s === null) return deny("agent");
    try { s.filter = "forged"; } catch (e) {}
    return deny(s.filter + " " + s.id + " " + s.depth + " " + s.parent + " " + Object.isFrozen(s));
  },
});`
	type testCase struct {
		info *chain.SubrequestInfo
		want string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		f := load(t, src, Options{})
		r := req(t, "GET", "https://api.github.com/x", nil)
		r.Subrequest = tc.info
		resp, err := f.Handle(r, upstream("x"))
		require.NoError(t, err)
		require.NotNil(t, resp.Denial)
		assert.Equal(t, tc.want, resp.Denial.Reason)
	}

	t.Run("null for an agent request", func(t *testing.T) {
		tester(t, testCase{want: "agent"})
	})
	t.Run("frozen info for a subrequest", func(t *testing.T) {
		tester(t, testCase{
			info: &chain.SubrequestInfo{Filter: "git-protect", Depth: 2, Parent: "POST github.com/o/r.git/git-receive-pack"},
			want: "git-protect null 2 POST github.com/o/r.git/git-receive-pack true",
		})
	})
	t.Run("the placement id when it has one", func(t *testing.T) {
		tester(t, testCase{
			info: &chain.SubrequestInfo{Filter: "git-protect", ID: "protect-main", Depth: 1, Parent: "POST x"},
			want: "git-protect protect-main 1 POST x true",
		})
	})
}

func TestPlaceholder(t *testing.T) {
	type testCase struct {
		src   string
		check func(string) error
		// deny is the expected denial reason, "" to skip.
		deny    string
		wantErr string
		verify  func(t *testing.T, sub *fakeSub, reason string)
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		sub := &fakeSub{}
		env := &chain.Env{Placeholder: tc.check, Subrequest: sub.do}
		f := load(t, tc.src, Options{Env: env, ID: "probe-id"})
		resp, err := f.Handle(req(t, "GET", "https://x/", nil), upstream("x"))
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		require.NotNil(t, resp.Denial)
		if tc.deny != "" {
			assert.Equal(t, tc.deny, resp.Denial.Reason)
		}
		if tc.verify != nil {
			tc.verify(t, sub, resp.Denial.Reason)
		}
	}
	oneTime := regexp.MustCompile(`^bouncer-placeholder-gitlab-pat-[0-9a-f]{16}$`)

	t.Run("each call returns a new one-time string for the credential", func(t *testing.T) {
		tester(t, testCase{
			src: `import { defineFilter, deny, placeholder } from "bouncer";
export default defineFilter({
  onRequest() {
    return deny(placeholder("gitlab-pat") + " " + placeholder("gitlab-pat"));
  },
});`,
			verify: func(t *testing.T, _ *fakeSub, reason string) {
				t.Helper()
				parts := strings.Split(reason, " ")
				require.Len(t, parts, 2)
				assert.Regexp(t, oneTime, parts[0])
				assert.Regexp(t, oneTime, parts[1])
				assert.NotEqual(t, parts[0], parts[1])
			},
		})
	})
	t.Run("the run's placeholders and the placement id go with its subrequests", func(t *testing.T) {
		tester(t, testCase{
			src: `import { defineFilter, deny, placeholder, subrequest } from "bouncer";
export default defineFilter({
  async onRequest() {
    const p = placeholder("gitlab-pat");
    await subrequest({ url: "https://gitlab.example.com/api", headers: { "Private-Token": p } });
    return deny(p);
  },
});`,
			verify: func(t *testing.T, sub *fakeSub, reason string) {
				t.Helper()
				assert.Equal(t, map[string]string{reason: "gitlab-pat"}, sub.caller.Placeholders)
				assert.Equal(t, "probe-id", sub.caller.ID)
				assert.Equal(t, reason, sub.spec.Header.Get("Private-Token"))
			},
		})
	})
	t.Run("throws when the check refuses the credential", func(t *testing.T) {
		tester(t, testCase{
			src: `import { defineFilter, deny, placeholder } from "bouncer";
export default defineFilter({ onRequest() { return deny(placeholder("gitlab-pat")); } });`,
			check: func(name string) error {
				return errors.New(`credential "` + name + `" does not allow subrequest`)
			},
			wantErr: `placeholder: credential "gitlab-pat" does not allow subrequest`,
		})
	})
	t.Run("throws at module top level", func(t *testing.T) {
		_, err := Load(Options{Path: writeFilter(t, t.TempDir(), "f.ts", `import { defineFilter, deny, placeholder } from "bouncer";
const p = placeholder("gitlab-pat");
export default defineFilter({ onRequest() { return deny(p); } });`)})
		require.ErrorContains(t, err, "placeholder() can only be called while handling a request")
	})
}

func TestPlaceholderExpires(t *testing.T) {
	sub := &fakeSub{}
	f := load(t, `import { defineFilter, deny, placeholder, subrequest } from "bouncer";
let kept = "";
export default defineFilter({
  async onRequest() {
    if (kept === "") {
      kept = placeholder("gitlab-pat");
      return deny("first");
    }
    await subrequest({ url: "https://gitlab.example.com/api", headers: { "Private-Token": kept } });
    return deny("second");
  },
});`, Options{Env: &chain.Env{Subrequest: sub.do}})
	_, err := f.Handle(req(t, "GET", "https://x/", nil), upstream("x"))
	require.NoError(t, err)
	_, err = f.Handle(req(t, "GET", "https://x/", nil), upstream("x"))
	require.NoError(t, err)
	require.NotEmpty(t, sub.spec.Header.Get("Private-Token"), "the second run reused the first run's string")
	assert.Empty(t, sub.caller.Placeholders, "a string from an earlier run is not this run's placeholder")
}

func TestSubrequestOrigin(t *testing.T) {
	t.Run("ask and requestClaim carry the origin", func(t *testing.T) {
		var askOrigin string
		claimer := &recordingClaims{}
		env := &chain.Env{
			Approver: approver(func(r chain.AskRequest) bool { askOrigin = r.Origin; return true }),
			Claims:   claimer,
		}
		f := load(t, `import { defineFilter, ask, requestClaim } from "bouncer";
export default defineFilter({
  async onRequest(req, next) {
    await ask("ok?");
    await requestClaim("repository", "github.com/o/r", "ok?");
    return next(req);
  },
});`, Options{Env: env})
		r := req(t, "GET", "https://api.github.com/x", nil)
		r.Subrequest = &chain.SubrequestInfo{Filter: "outer", Depth: 1, Parent: "POST github.com/o/r.git/git-receive-pack"}
		_, err := f.Handle(r, upstream("x"))
		require.NoError(t, err)
		want := "subrequest from outer for POST github.com/o/r.git/git-receive-pack"
		assert.Equal(t, want, askOrigin)
		assert.Equal(t, want, claimer.origin)
	})
}

// recordingClaims allows every claim request and records its origin.
type recordingClaims struct {
	origin string
}

func (c *recordingClaims) RequestClaim(_ context.Context, r chain.ClaimRequest) (bool, error) {
	c.origin = r.Origin
	return true, nil
}

package jsfilter

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/internal/bouncer/gitproto"
	"github.com/pastdev/agentcon/internal/bouncer/kv"
)

func writeFilter(t *testing.T, dir, name, src string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	err := os.WriteFile(p, []byte(src), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func load(t *testing.T, src string, opts Options) *Filter {
	t.Helper()
	opts.Path = writeFilter(t, t.TempDir(), "f.ts", src)
	f, err := Load(opts)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func req(_ *testing.T, method, raw string, body []byte) *chain.Request {
	u, _ := url.Parse(raw)
	return &chain.Request{Ctx: context.Background(), Transport: chain.TransportHTTP, Method: method, URL: u,
		Header: http.Header{}, Body: chain.BytesBody(body), Session: &chain.Session{ID: "s1"}}
}

func upstream(body string) chain.Handler {
	return func(*chain.Request) (*chain.Response, error) {
		return &chain.Response{Status: 200, Header: http.Header{"Content-Type": {"text/plain"}}, Body: chain.BytesBody([]byte(body))}, nil
	}
}

type approver func(chain.AskRequest) bool

func (a approver) Ask(_ context.Context, r chain.AskRequest) (bool, error) { return a(r), nil }

func sessReq(t *testing.T, id string) *chain.Request {
	r := req(t, "GET", "https://x/", nil)
	r.Session = &chain.Session{ID: id}
	return r
}

func TestLoad(t *testing.T) {
	type testCase struct {
		opts    Options
		wantErr string
		anyErr  bool
		budget  bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		start := time.Now()
		_, err := Load(tc.opts)
		if tc.anyErr {
			if err == nil {
				t.Fatal("expected load error")
			}
			return
		}
		if tc.wantErr == "" {
			if err != nil {
				t.Fatal(err)
			}
			return
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("expected %q, got %v", tc.wantErr, err)
		}
		if tc.budget && time.Since(start) > 2*time.Second {
			t.Fatal("top-level spin was not interrupted near the budget")
		}
	}

	t.Run("rejects a syntax error", func(t *testing.T) {
		dir := t.TempDir()
		tester(t, testCase{
			opts:   Options{Path: writeFilter(t, dir, "syntax.ts", `export default { onRequest( };`)},
			anyErr: true,
		})
	})
	t.Run("rejects a filter with no hooks", func(t *testing.T) {
		dir := t.TempDir()
		tester(t, testCase{
			opts:   Options{Path: writeFilter(t, dir, "nohooks.ts", `export default { name: "x" };`)},
			anyErr: true,
		})
	})
	t.Run("rejects a module with no default export", func(t *testing.T) {
		dir := t.TempDir()
		tester(t, testCase{
			opts:   Options{Path: writeFilter(t, dir, "nodef.ts", `export const x = 1;`)},
			anyErr: true,
		})
	})
	t.Run("rejects a missing relative import", func(t *testing.T) {
		dir := t.TempDir()
		tester(t, testCase{
			opts:   Options{Path: writeFilter(t, dir, "import.ts", `import x from "./missing"; export default x;`)},
			anyErr: true,
		})
	})
	t.Run("bounds a spinning top-level module", func(t *testing.T) {
		dir := t.TempDir()
		p := writeFilter(t, dir, "spin.ts", `const t0 = Date.now(); while (Date.now() - t0 < 5000) {}
export default { onRequest(req, next) { return next(req); } };`)
		tester(t, testCase{
			opts:    Options{Path: p, Timeout: 100 * time.Millisecond},
			wantErr: "top-level",
			budget:  true,
		})
	})
}

func TestHandle(t *testing.T) {
	type testCase struct {
		h            chain.Handler
		req          *chain.Request
		wantDenial   string
		wantBy       string
		wantStatus   int
		wantBody     string
		wantHeader   string
		headerKey    string
		allow        *bool
		wantReasonIn string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		resp, err := tc.h(tc.req)
		if err != nil {
			t.Fatal(err)
		}
		if tc.wantDenial != "" {
			if resp.Denial == nil || resp.Denial.Reason != tc.wantDenial {
				t.Fatalf("expected denial, got %+v", resp.Denial)
			}
			if tc.wantBy != "" && resp.Denial.By != tc.wantBy {
				t.Fatalf("expected denial, got %+v", resp.Denial)
			}
			return
		}
		if tc.wantReasonIn != "" {
			if resp.Denial == nil || !strings.Contains(resp.Denial.Reason, tc.wantReasonIn) {
				t.Fatalf("expected denial, got %+v", resp.Denial)
			}
			return
		}
		if tc.allow != nil {
			if got := resp.Denial == nil; got != *tc.allow {
				t.Errorf("allowed=%v want %v (%+v)", got, *tc.allow, resp.Denial)
			}
			return
		}
		if resp.Denial != nil {
			t.Fatalf("%+v %v", resp, err)
		}
		if tc.wantStatus != 0 && resp.Status != tc.wantStatus {
			t.Fatalf("status=%d", resp.Status)
		}
		if tc.wantBody != "" {
			b, err := io.ReadAll(resp.Body.Reader())
			if err != nil {
				t.Fatal(err)
			}
			if string(b) != tc.wantBody {
				t.Fatalf("status=%d body=%q", resp.Status, b)
			}
		}
		if tc.headerKey != "" && resp.Header.Get(tc.headerKey) != tc.wantHeader {
			t.Fatalf("status=%d headers=%v", resp.Status, resp.Header)
		}
	}

	t.Run("denies a git push to a blocked branch", func(t *testing.T) {
		f := load(t, `
import { defineFilter, deny } from "bouncer";
export default defineFilter<{ branches: string[] }>({
  async onRequest(req, next, ctx) {
    if (req.git?.service === "receive-pack") {
      const updates = await req.git.refUpdates();
      const hit = updates.find(u => ctx.config.branches.includes(u.ref.replace("refs/heads/", "")));
      if (hit) return deny(`+"`push to ${hit.ref} blocked`"+`);
    }
    return next(req);
  },
});`, Options{Config: map[string]any{"branches": []any{"foo"}}})
		h := chain.Build([]chain.Filter{f}, upstream("ok"))
		a, b := strings.Repeat("a", 40), strings.Repeat("b", 40)
		body := gitproto.BuildPush([]gitproto.RefUpdate{{OldOID: a, NewOID: b, Ref: "refs/heads/feature"}, {OldOID: a, NewOID: b, Ref: "refs/heads/foo"}}, nil, nil)
		tester(t, testCase{
			h:          h,
			req:        req(t, "POST", "https://gitlab.com/g/p.git/git-receive-pack", body),
			wantDenial: "push to refs/heads/foo blocked",
			wantBy:     "f",
		})
	})
	t.Run("allows a git push that misses the blocked branch", func(t *testing.T) {
		f := load(t, `
import { defineFilter, deny } from "bouncer";
export default defineFilter<{ branches: string[] }>({
  async onRequest(req, next, ctx) {
    if (req.git?.service === "receive-pack") {
      const updates = await req.git.refUpdates();
      const hit = updates.find(u => ctx.config.branches.includes(u.ref.replace("refs/heads/", "")));
      if (hit) return deny(`+"`push to ${hit.ref} blocked`"+`);
    }
    return next(req);
  },
});`, Options{Config: map[string]any{"branches": []any{"foo"}}})
		h := chain.Build([]chain.Filter{f}, upstream("ok"))
		a, b := strings.Repeat("a", 40), strings.Repeat("b", 40)
		body := gitproto.BuildPush([]gitproto.RefUpdate{{OldOID: a, NewOID: b, Ref: "refs/heads/feature"}}, nil, nil)
		allow := true
		tester(t, testCase{h: h, req: req(t, "POST", "https://gitlab.com/g/p.git/git-receive-pack", body), allow: &allow})
	})
	t.Run("rewrites a nested filter response", func(t *testing.T) {
		outer := load(t, `
import { defineFilter } from "bouncer";
export default defineFilter({
  name: "outer",
  async onRequest(req, next) {
    req.headers.set("X-Outer", "1");
    const res = await next(req);
    const text = await res.body.text();
    res.body.set(text.replace("SECRET", "[redacted]"));
    res.headers.set("X-Seen", String(res.status));
    return res;
  },
});`, Options{})
		inner := load(t, `
export default {
  name: "inner",
  async onRequest(req, next) {
    if (req.headers.get("x-outer") !== "1") throw new Error("outer header missing");
    const res = await next(req);
    res.setStatus(201);
    return res;
  },
};`, Options{})
		h := chain.Build([]chain.Filter{outer, inner}, upstream("token=SECRET"))
		tester(t, testCase{
			h:          h,
			req:        req(t, "GET", "https://x/", nil),
			wantStatus: 201,
			wantBody:   "token=[redacted]",
			headerKey:  "X-Seen",
			wantHeader: "201",
		})
	})
	t.Run("denies a response that contains a private key", func(t *testing.T) {
		f := load(t, `
import { defineFilter, deny } from "bouncer";
export default defineFilter({
  async onResponse(res, req) {
    if ((await res.body.text()).includes("BEGIN PRIVATE KEY")) return deny("response contained a private key");
  },
});`, Options{})
		h := chain.Build([]chain.Filter{f}, upstream("-----BEGIN PRIVATE KEY-----"))
		allow := false
		tester(t, testCase{h: h, req: req(t, "GET", "https://x/", nil), allow: &allow})
	})
	t.Run("allows a response without a private key", func(t *testing.T) {
		f := load(t, `
import { defineFilter, deny } from "bouncer";
export default defineFilter({
  async onResponse(res, req) {
    if ((await res.body.text()).includes("BEGIN PRIVATE KEY")) return deny("response contained a private key");
  },
});`, Options{})
		h := chain.Build([]chain.Filter{f}, upstream("fine"))
		resp, err := h(req(t, "GET", "https://x/", nil))
		if err != nil {
			t.Fatal(err)
		}
		if resp.Denial != nil || resp.Status != 200 {
			t.Fatalf("unexpected %+v", resp)
		}
	})
	t.Run("responds with a credential value", func(t *testing.T) {
		env := &chain.Env{Credential: func(_ context.Context, name string) (string, error) {
			if name != "smoke" {
				return "", errors.New("unknown credential")
			}
			return "from-vault", nil
		}}
		f := load(t, `
import { defineFilter, credential, respond } from "bouncer";
export default defineFilter({
  onRequest() {
    return respond(200, credential("smoke") + "\n", { "Content-Type": "text/plain" });
  },
});`, Options{Env: env})
		h := chain.Build([]chain.Filter{f}, upstream("should-not-run"))
		tester(t, testCase{
			h:          h,
			req:        req(t, "GET", "https://vault.test/", nil),
			wantStatus: 200,
			wantBody:   "from-vault\n",
		})
	})
	t.Run("responds with json for a disallowed channel", func(t *testing.T) {
		f := load(t, `
import { defineFilter, respond } from "bouncer";
export default defineFilter({
  async onRequest(req, next) {
    const body = await req.body.json();
    if (body.channel !== "#agent-bot") return respond(422, { ok: false, error: "channel not allowed" }, { "Content-Type": "application/json" });
    return next(req);
  },
});`, Options{})
		h := chain.Build([]chain.Filter{f}, upstream("posted"))
		tester(t, testCase{
			h:          h,
			req:        req(t, "POST", "https://slack.com/api/chat.postMessage", []byte(`{"channel":"#general"}`)),
			wantStatus: 422,
			wantBody:   `{"ok":false,"error":"channel not allowed"}`,
			headerKey:  "Content-Type",
			wantHeader: "application/json",
		})
	})
	t.Run("uses kv and ask across requests", func(t *testing.T) {
		store, err := kv.Open("")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = store.Close() }()
		var prompts []string
		env := &chain.Env{Approver: approver(func(a chain.AskRequest) bool { prompts = append(prompts, a.Prompt); return a.Prompt == "push #2?" })}
		f := load(t, `
import { defineFilter, deny, ask, kv } from "bouncer";
export default defineFilter({
  async onRequest(req, next) {
    const n = kv.incr("count", { ttl: "1h" });
    if (n > 1 && !(await ask("push #" + n + "?"))) return deny("not approved");
    return next(req);
  },
});`, Options{Env: env, KV: store})
		h := chain.Build([]chain.Filter{f}, upstream("ok"))
		for i, want := range []bool{true, true, false} {
			resp, err := h(req(t, "GET", "https://x/", nil))
			if err != nil {
				t.Fatal(err)
			}
			if got := resp.Denial == nil; got != want {
				t.Errorf("call %d: allowed=%v want %v (%+v)", i+1, got, want, resp.Denial)
			}
		}
		if len(prompts) != 2 {
			t.Errorf("prompts: %v", prompts)
		}
	})
	t.Run("fails closed on a cpu budget timeout", func(t *testing.T) {
		spin := load(t, `export default { onRequest() { for (;;) {} } };`, Options{Timeout: 50 * time.Millisecond})
		start := time.Now()
		resp, err := chain.Build([]chain.Filter{spin}, upstream("ok"))(req(t, "GET", "https://x/", nil))
		if err != nil {
			t.Fatal(err)
		}
		if resp.Denial == nil || !strings.Contains(resp.Denial.Reason, "CPU budget") {
			t.Fatalf("expected timeout denial, got %+v", resp.Denial)
		}
		if time.Since(start) > 2*time.Second {
			t.Fatal("timeout did not interrupt")
		}
	})
	t.Run("excludes blocked upstream time from the budget", func(t *testing.T) {
		pass := load(t, `export default { async onRequest(req, next) { return next(req); } };`, Options{Timeout: 20 * time.Millisecond})
		slow := func(*chain.Request) (*chain.Response, error) {
			time.Sleep(100 * time.Millisecond)
			return &chain.Response{Status: 200}, nil
		}
		resp, err := chain.Build([]chain.Filter{pass}, slow)(req(t, "GET", "https://x/", nil))
		if err != nil {
			t.Fatal(err)
		}
		if resp.Denial != nil {
			t.Fatalf("blocked time counted against budget: %+v", resp.Denial)
		}
	})
	t.Run("returns empty arrays from getAll", func(t *testing.T) {
		f := load(t, `import { deny } from "bouncer";
export default { onRequest(req, next) {
  const q = req.query.getAll("missing"), h = req.headers.getAll("X-Missing");
  if (!Array.isArray(q) || q.length || !Array.isArray(h) || h.length) return deny("not empty arrays");
  return next(req);
} };`, Options{})
		resp, err := chain.Build([]chain.Filter{f}, upstream("ok"))(req(t, "GET", "https://x/", nil))
		if err != nil {
			t.Fatal(err)
		}
		if resp.Denial != nil {
			t.Fatal(resp.Denial.Reason)
		}
	})
	t.Run("counts in-memory host calls against the budget", func(t *testing.T) {
		f := load(t, `export default { async onRequest(req, next) { for (;;) { await req.body.peek(1); } } };`, Options{Timeout: 100 * time.Millisecond})
		start := time.Now()
		resp, err := chain.Build([]chain.Filter{f}, upstream("ok"))(req(t, "POST", "https://x/", []byte("abc")))
		if err != nil {
			t.Fatal(err)
		}
		if resp.Denial == nil || !strings.Contains(resp.Denial.Reason, "CPU budget") {
			t.Fatalf("expected budget denial, got %+v", resp.Denial)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("100ms budget took %v: in-memory host calls aren't being counted", elapsed)
		}
	})
	t.Run("fails closed with a typescript source location", func(t *testing.T) {
		f := load(t, `
import { defineFilter } from "bouncer";
interface X { a: number }
export default defineFilter({
  onRequest(req, next) {
    const x: X = { a: 1 };
    throw new Error("kaboom " + x.a);
  },
});`, Options{})
		resp, err := chain.Build([]chain.Filter{f}, upstream("ok"))(req(t, "GET", "https://x/", nil))
		if err != nil {
			t.Fatal(err)
		}
		if resp.Denial == nil || !strings.Contains(resp.Denial.Reason, "kaboom 1") {
			t.Fatalf("%+v", resp.Denial)
		}
		if !strings.Contains(resp.Denial.Reason, "f.ts:7") {
			t.Errorf("stack should point at the TS source line: %s", resp.Denial.Reason)
		}
	})
	t.Run("fails closed when onRequest returns nothing", func(t *testing.T) {
		noReturn := load(t, `export default { onRequest(req, next) { next(req); } };`, Options{})
		resp, err := chain.Build([]chain.Filter{noReturn}, upstream("ok"))(req(t, "GET", "https://x/", nil))
		if err != nil {
			t.Fatal(err)
		}
		if resp.Denial == nil || !strings.Contains(resp.Denial.Reason, "returned nothing") {
			t.Fatalf("%+v", resp.Denial)
		}
	})
	t.Run("resolves relative imports and graphql fields", func(t *testing.T) {
		dir := t.TempDir()
		writeFilter(t, dir, "lib.ts", `export const DANGEROUS = new Set(["deleteRepository"]);`)
		p := writeFilter(t, dir, "gql.ts", `
import { defineFilter, deny } from "bouncer";
import { DANGEROUS } from "./lib";
export default defineFilter({
  async onRequest(req, next) {
    const ops = await req.graphql();
    for (const op of ops ?? []) for (const f of op.fields) if (DANGEROUS.has(f)) return deny(f);
    return next(req);
  },
});`)
		f, err := Load(Options{Path: p})
		if err != nil {
			t.Fatal(err)
		}
		h := chain.Build([]chain.Filter{f}, upstream("ok"))
		tester(t, testCase{
			h:          h,
			req:        req(t, "POST", "https://api.github.com/graphql", []byte(`{"query":"mutation { deleteRepository(input:{}) { clientMutationId } }"}`)),
			wantDenial: "deleteRepository",
		})
	})
	t.Run("serves concurrent requests from separate vms", func(t *testing.T) {
		f := load(t, `export default { async onRequest(req, next) { const r = await next(req); return r; } };`, Options{})
		h := chain.Build([]chain.Filter{f}, func(*chain.Request) (*chain.Response, error) {
			time.Sleep(10 * time.Millisecond)
			return &chain.Response{Status: 200}, nil
		})
		done := make(chan bool)
		for i := 0; i < 20; i++ {
			go func() {
				resp, _ := h(req(t, "GET", "https://x/", nil))
				done <- resp.Denial == nil
			}()
		}
		for i := 0; i < 20; i++ {
			if !<-done {
				t.Fatal("concurrent request denied")
			}
		}
	})
	t.Run("does not leak module state across sessions", func(t *testing.T) {
		f := load(t, `import { respond } from "bouncer"; let last = "none";
export default { onRequest(req) { const p = last; last = req.session.id; return respond(200, p); } };`, Options{})
		h := chain.Build([]chain.Filter{f}, upstream("ok"))
		for i := 0; i < 5; i++ {
			resp, err := h(sessReq(t, "session-A"))
			if err != nil {
				t.Fatal(err)
			}
			b, err := io.ReadAll(resp.Body.Reader())
			if err != nil {
				t.Fatal(err)
			}
			if string(b) == "session-A" {
				continue
			}
		}
		resp, err := h(sessReq(t, "session-B"))
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(resp.Body.Reader())
		if err != nil {
			t.Fatal(err)
		}
		if string(b) == "session-A" {
			t.Fatalf("session B saw session A's state: %q", b)
		}
	})
	t.Run("rejects a stale next callback", func(t *testing.T) {
		var forwarded int
		term := func(*chain.Request) (*chain.Response, error) {
			forwarded++
			return &chain.Response{Status: 200}, nil
		}
		f := load(t, `import { deny } from "bouncer"; let saved = null;
export default { async onRequest(req, next) {
  if (!saved) { saved = next; return deny("first"); }
  try { await saved(req); } catch (e) { return deny("stale: " + e); }
  return deny("second");
} };`, Options{})
		h := chain.Build([]chain.Filter{f}, term)
		_, _ = h(sessReq(t, "s1"))
		resp, err := h(sessReq(t, "s1"))
		if err != nil {
			t.Fatal(err)
		}
		if forwarded != 0 {
			t.Fatalf("stale next() forwarded %d requests upstream", forwarded)
		}
		if resp.Denial == nil || !strings.Contains(resp.Denial.Reason, "stale") {
			t.Fatalf("expected stale-next denial, got %+v", resp.Denial)
		}
	})
	t.Run("hits the budget on a fast ask loop", func(t *testing.T) {
		env := &chain.Env{Approver: approver(func(chain.AskRequest) bool { return true })}
		f := load(t, `import { ask } from "bouncer";
export default { async onRequest(req, next) {
  const t0 = Date.now();
  while (Date.now() - t0 < 5000) { await ask("x"); for (let j = 0; j < 50; j++) {} }
  return next(req);
} };`, Options{Timeout: 50 * time.Millisecond, Env: env})
		start := time.Now()
		resp, err := chain.Build([]chain.Filter{f}, upstream("ok"))(req(t, "GET", "https://x/", nil))
		if err != nil {
			t.Fatal(err)
		}
		if resp.Denial == nil {
			t.Fatal("fast ask() loop was allowed")
		}
		if time.Since(start) > 2*time.Second {
			t.Fatalf("ask() loop ran %v past a 50ms budget", time.Since(start))
		}
	})
}

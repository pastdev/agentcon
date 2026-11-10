package chain

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/pastdev/agentcon/internal/bouncer/gitproto"
	"github.com/pastdev/agentcon/pkg/bouncer/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func httpReq(t *testing.T, method, rawURL string, body []byte) *Request {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return &Request{Ctx: context.Background(), Transport: TransportHTTP, Method: method, URL: u,
		Header: http.Header{}, Body: BytesBody(body), Service: "gitlab"}
}

func upstreamOK(*Request) (*Response, error) { return &Response{Status: 200}, nil }

func loadRules(t *testing.T, yml string) *config.Service {
	t.Helper()
	cfg, err := config.Parse([]byte(`
credentials: {gl: {token: {source: keyring}}}
profiles:
  p:
    http:
      - name: gitlab
        hosts: [gitlab.com]
        credential: gl
`+yml), "/tmp/c.yaml")
	require.NoError(t, err)
	return cfg.Profiles["p"].HTTP[0]
}

type approverFunc func(AskRequest) bool

func (f approverFunc) Ask(_ context.Context, a AskRequest) (bool, error) { return f(a), nil }

type filterFunc func(*Request, Handler) (*Response, error)

func (f filterFunc) Name() string                                    { return "func" }
func (f filterFunc) Handle(r *Request, n Handler) (*Response, error) { return f(r, n) }

func TestBuild(t *testing.T) {
	type testCase struct {
		h          Handler
		req        *Request
		allow      bool
		wantStatus int
		wantDenial bool
		intact     []byte
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		resp, err := tc.h(tc.req)
		require.NoError(t, err)
		if tc.wantStatus != 0 {
			require.Equal(t, tc.wantStatus, resp.Status)
			require.Nil(t, resp.Denial)
		} else {
			assert.Equal(t, tc.allow, resp.Denial == nil, "allowed (%+v)", resp.Denial)
		}
		if tc.wantDenial {
			require.NotNil(t, resp.Denial)
		}
		if tc.intact != nil {
			fwd, err := io.ReadAll(tc.req.Body.Reader())
			require.NoError(t, err)
			assert.Equal(t, tc.intact, fwd, "body altered by inspection")
		}
	}

	t.Run("allows a matching path", func(t *testing.T) {
		svc := loadRules(t, `
        rules:
          - action: allow
            path: /allowed
`)
		h := Build([]Filter{NewRules(svc, nil).WithUnmatched(config.UnmatchedTunnel)}, func(req *Request) (*Response, error) {
			if req.SkipCredential {
				return &Response{Status: 204}, nil
			}
			return &Response{Status: 200}, nil
		})
		tester(t, testCase{h: h, req: httpReq(t, "GET", "https://gitlab.com/allowed", nil), wantStatus: 200})
	})
	t.Run("skips credentials for an unmatched tunnel", func(t *testing.T) {
		svc := loadRules(t, `
        rules:
          - action: allow
            path: /allowed
`)
		h := Build([]Filter{NewRules(svc, nil).WithUnmatched(config.UnmatchedTunnel)}, func(req *Request) (*Response, error) {
			if req.SkipCredential {
				return &Response{Status: 204}, nil
			}
			return &Response{Status: 200}, nil
		})
		tester(t, testCase{h: h, req: httpReq(t, "GET", "https://gitlab.com/other", nil), wantStatus: 204})
	})
	t.Run("denies an unmatched path when unmatched is deny", func(t *testing.T) {
		svc := loadRules(t, `
        rules:
          - action: allow
            path: /allowed
`)
		h := Build([]Filter{NewRules(svc, nil).WithUnmatched(config.UnmatchedDeny)}, upstreamOK)
		tester(t, testCase{h: h, req: httpReq(t, "GET", "https://gitlab.com/other", nil), allow: false})
	})

	gitlabScope := func(t *testing.T) Handler {
		t.Helper()
		svc := loadRules(t, `
        rules:
          - action: allow
            gitlab_project: mygroup/myproj
          - action: allow
            methods: [GET]
            path: /api/v4/user
`)
		env := &Env{Resolver: func(_ context.Context, _, _, p string) (int64, error) {
			if p == "mygroup/myproj" {
				return 4242, nil
			}
			return 0, nil
		}}
		return Build([]Filter{NewRules(svc, env)}, upstreamOK)
	}
	t.Run("allows GET of the encoded gitlab project", func(t *testing.T) {
		tester(t, testCase{h: gitlabScope(t), req: httpReq(t, "GET", "https://gitlab.com/api/v4/projects/mygroup%2Fmyproj", nil), allow: true})
	})
	t.Run("allows GET of a case-insensitive project subpath", func(t *testing.T) {
		tester(t, testCase{h: gitlabScope(t), req: httpReq(t, "GET", "https://gitlab.com/api/v4/projects/MyGroup%2FMyProj/merge_requests", nil), allow: true})
	})
	t.Run("allows GET by numeric project id", func(t *testing.T) {
		tester(t, testCase{h: gitlabScope(t), req: httpReq(t, "GET", "https://gitlab.com/api/v4/projects/4242/issues", nil), allow: true})
	})
	t.Run("denies GET of a different numeric id", func(t *testing.T) {
		tester(t, testCase{h: gitlabScope(t), req: httpReq(t, "GET", "https://gitlab.com/api/v4/projects/4243/issues", nil), allow: false})
	})
	t.Run("denies GET of a different project path", func(t *testing.T) {
		tester(t, testCase{h: gitlabScope(t), req: httpReq(t, "GET", "https://gitlab.com/api/v4/projects/mygroup%2Fother/issues", nil), allow: false})
	})
	t.Run("denies GET of a path-prefix sibling", func(t *testing.T) {
		tester(t, testCase{h: gitlabScope(t), req: httpReq(t, "GET", "https://gitlab.com/api/v4/projects/mygroup%2Fmyproj-evil", nil), allow: false})
	})
	t.Run("denies GET of the projects collection", func(t *testing.T) {
		tester(t, testCase{h: gitlabScope(t), req: httpReq(t, "GET", "https://gitlab.com/api/v4/projects", nil), allow: false})
	})
	t.Run("allows GET /api/v4/user", func(t *testing.T) {
		tester(t, testCase{h: gitlabScope(t), req: httpReq(t, "GET", "https://gitlab.com/api/v4/user", nil), allow: true})
	})
	t.Run("denies POST /api/v4/user", func(t *testing.T) {
		tester(t, testCase{h: gitlabScope(t), req: httpReq(t, "POST", "https://gitlab.com/api/v4/user", nil), allow: false})
	})
	t.Run("denies GET of a group", func(t *testing.T) {
		tester(t, testCase{h: gitlabScope(t), req: httpReq(t, "GET", "https://gitlab.com/api/v4/groups/mygroup", nil), allow: false})
	})
	t.Run("denies POST graphql", func(t *testing.T) {
		tester(t, testCase{h: gitlabScope(t), req: httpReq(t, "POST", "https://gitlab.com/api/graphql", nil), allow: false})
	})
	t.Run("allows git upload-pack for the project", func(t *testing.T) {
		tester(t, testCase{h: gitlabScope(t), req: httpReq(t, "GET", "https://gitlab.com/mygroup/myproj.git/info/refs?service=git-upload-pack", nil), allow: true})
	})
	t.Run("denies git upload-pack for another project", func(t *testing.T) {
		tester(t, testCase{h: gitlabScope(t), req: httpReq(t, "POST", "https://gitlab.com/mygroup/other.git/git-upload-pack", nil), allow: false})
	})

	gitlabSub := func(t *testing.T) Handler {
		t.Helper()
		svc := loadRules(t, `
        rules:
          - action: deny
            reason: secrets and membership are off-limits
            gitlab_project: {path: mygroup/myproj, subpaths: ["variables/**", "members/**"]}
          - action: deny
            methods: [DELETE, PUT]
            gitlab_project: {path: mygroup/myproj, subpaths: [""]}
          - action: allow
            gitlab_project: mygroup/myproj
`)
		return Build([]Filter{NewRules(svc, &Env{Resolver: func(context.Context, string, string, string) (int64, error) { return 7, nil }})}, upstreamOK)
	}
	t.Run("allows GET of the gitlab project root", func(t *testing.T) {
		tester(t, testCase{h: gitlabSub(t), req: httpReq(t, "GET", "https://gitlab.com/api/v4/projects/mygroup%2Fmyproj", nil), allow: true})
	})
	t.Run("denies DELETE of the gitlab project root", func(t *testing.T) {
		tester(t, testCase{h: gitlabSub(t), req: httpReq(t, "DELETE", "https://gitlab.com/api/v4/projects/mygroup%2Fmyproj", nil), allow: false})
	})
	t.Run("denies DELETE of the numeric project root", func(t *testing.T) {
		tester(t, testCase{h: gitlabSub(t), req: httpReq(t, "DELETE", "https://gitlab.com/api/v4/projects/7", nil), allow: false})
	})
	t.Run("allows DELETE of a project issue", func(t *testing.T) {
		tester(t, testCase{h: gitlabSub(t), req: httpReq(t, "DELETE", "https://gitlab.com/api/v4/projects/7/issues/3", nil), allow: true})
	})
	t.Run("denies GET of project variables", func(t *testing.T) {
		tester(t, testCase{h: gitlabSub(t), req: httpReq(t, "GET", "https://gitlab.com/api/v4/projects/7/variables", nil), allow: false})
	})
	t.Run("denies GET of a project variable key", func(t *testing.T) {
		tester(t, testCase{h: gitlabSub(t), req: httpReq(t, "GET", "https://gitlab.com/api/v4/projects/mygroup%2Fmyproj/variables/KEY", nil), allow: false})
	})
	t.Run("denies POST of project members", func(t *testing.T) {
		tester(t, testCase{h: gitlabSub(t), req: httpReq(t, "POST", "https://gitlab.com/api/v4/projects/7/members", nil), allow: false})
	})
	t.Run("allows git upload-pack under project subpath rules", func(t *testing.T) {
		tester(t, testCase{h: gitlabSub(t), req: httpReq(t, "GET", "https://gitlab.com/mygroup/myproj.git/info/refs?service=git-upload-pack", nil), allow: true})
	})

	gitPush := func(t *testing.T) Handler {
		t.Helper()
		svc := loadRules(t, `
        default: allow
        rules:
          - action: deny
            reason: protected branch
            git: {service: receive-pack, refs: [refs/heads/main, refs/heads/release/*]}
          - action: deny
            git: {service: receive-pack, updates: [delete]}
`)
		return Build([]Filter{NewRules(svc, nil)}, upstreamOK)
	}
	push := func(ups ...gitproto.RefUpdate) []byte {
		return gitproto.BuildPush(ups, []string{"report-status"}, nil)
	}
	oidA := strings.Repeat("a", 40)
	oidB := strings.Repeat("b", 40)
	t.Run("allows a feature branch push", func(t *testing.T) {
		body := push(gitproto.RefUpdate{OldOID: oidA, NewOID: oidB, Ref: "refs/heads/feature"})
		req := httpReq(t, "POST", "https://gitlab.com/g/p.git/git-receive-pack", body)
		tester(t, testCase{h: gitPush(t), req: req, allow: true, intact: body})
	})
	t.Run("denies a push that includes main", func(t *testing.T) {
		body := push(gitproto.RefUpdate{OldOID: oidA, NewOID: oidB, Ref: "refs/heads/feature"}, gitproto.RefUpdate{OldOID: oidA, NewOID: oidB, Ref: "refs/heads/main"})
		req := httpReq(t, "POST", "https://gitlab.com/g/p.git/git-receive-pack", body)
		tester(t, testCase{h: gitPush(t), req: req, allow: false, intact: body})
	})
	t.Run("denies a release glob push", func(t *testing.T) {
		body := push(gitproto.RefUpdate{OldOID: oidA, NewOID: oidB, Ref: "refs/heads/release/1.0"})
		req := httpReq(t, "POST", "https://gitlab.com/g/p.git/git-receive-pack", body)
		tester(t, testCase{h: gitPush(t), req: req, allow: false, intact: body})
	})
	t.Run("denies a delete update", func(t *testing.T) {
		body := push(gitproto.RefUpdate{OldOID: oidA, NewOID: gitproto.ZeroOID, Ref: "refs/heads/feature"})
		req := httpReq(t, "POST", "https://gitlab.com/g/p.git/git-receive-pack", body)
		tester(t, testCase{h: gitPush(t), req: req, allow: false, intact: body})
	})
	t.Run("denies a main push on a trailing-slash receive-pack url", func(t *testing.T) {
		body := push(gitproto.RefUpdate{OldOID: oidA, NewOID: oidB, Ref: "refs/heads/main"})
		req := httpReq(t, "POST", "https://gitlab.com/g/p.git/git-receive-pack/", body)
		req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
		tester(t, testCase{h: gitPush(t), req: req, allow: false})
	})
	t.Run("denies a main push on an unusual route with a receive-pack content type", func(t *testing.T) {
		body := push(gitproto.RefUpdate{OldOID: oidA, NewOID: oidB, Ref: "refs/heads/main"})
		req := httpReq(t, "POST", "https://gitlab.com/g/p/some-other-route", body)
		req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
		tester(t, testCase{h: gitPush(t), req: req, allow: false})
	})
	t.Run("allows a receive-pack ref advertisement", func(t *testing.T) {
		tester(t, testCase{h: gitPush(t), req: httpReq(t, "GET", "https://gitlab.com/g/p.git/info/refs?service=git-receive-pack", nil), allow: true})
	})

	gitTagAsk := func(t *testing.T, yes bool) Handler {
		t.Helper()
		svc := loadRules(t, `
        default: deny
        rules:
          - action: ask
            git: {service: receive-pack, refs: [refs/tags/*]}
            prompt: Push a git tag?
          - action: allow
            git: {}
`)
		return Build([]Filter{NewRules(svc, &Env{Approver: approverFunc(func(AskRequest) bool { return yes })})}, upstreamOK)
	}
	t.Run("asks on a tag push", func(t *testing.T) {
		body := push(gitproto.RefUpdate{OldOID: gitproto.ZeroOID, NewOID: oidB, Ref: "refs/tags/v0.1.0"})
		req := httpReq(t, "POST", "https://gitlab.com/g/p.git/git-receive-pack", body)
		tester(t, testCase{h: gitTagAsk(t, false), req: req, allow: false, intact: body})
	})
	t.Run("allows a tag push after ask yes", func(t *testing.T) {
		body := push(gitproto.RefUpdate{OldOID: gitproto.ZeroOID, NewOID: oidB, Ref: "refs/tags/v0.1.0"})
		req := httpReq(t, "POST", "https://gitlab.com/g/p.git/git-receive-pack", body)
		tester(t, testCase{h: gitTagAsk(t, true), req: req, allow: true, intact: body})
	})
	t.Run("allows a feature branch push when tags ask", func(t *testing.T) {
		body := push(gitproto.RefUpdate{OldOID: oidA, NewOID: oidB, Ref: "refs/heads/feature"})
		req := httpReq(t, "POST", "https://gitlab.com/g/p.git/git-receive-pack", body)
		tester(t, testCase{h: gitTagAsk(t, false), req: req, allow: true, intact: body})
	})

	graphqlMergeAsk := func(t *testing.T, yes bool) Handler {
		t.Helper()
		svc := loadRules(t, `
        default: deny
        rules:
          - action: ask
            methods: [POST]
            path: /graphql
            graphql: {operations: [mutation], fields: [mergePullRequest]}
            prompt: Merge a pull request?
          - action: allow
            methods: [POST]
            path: /graphql
`)
		return Build([]Filter{NewRules(svc, &Env{Approver: approverFunc(func(AskRequest) bool { return yes })})}, upstreamOK)
	}
	t.Run("asks on a graphql mergePullRequest", func(t *testing.T) {
		req := httpReq(t, "POST", "https://api.github.com/graphql",
			[]byte(`{"query":"mutation { mergePullRequest(input:{pullRequestId:\"x\"}) { clientMutationId } }"}`))
		tester(t, testCase{h: graphqlMergeAsk(t, false), req: req, allow: false})
	})
	t.Run("allows a graphql mergePullRequest after ask yes", func(t *testing.T) {
		req := httpReq(t, "POST", "https://api.github.com/graphql",
			[]byte(`{"query":"mutation { mergePullRequest(input:{pullRequestId:\"x\"}) { clientMutationId } }"}`))
		tester(t, testCase{h: graphqlMergeAsk(t, true), req: req, allow: true})
	})
	t.Run("allows a graphql query when merge asks", func(t *testing.T) {
		req := httpReq(t, "POST", "https://api.github.com/graphql", []byte(`{"query":"{ viewer { login } }"}`))
		tester(t, testCase{h: graphqlMergeAsk(t, false), req: req, allow: true})
	})

	graphqlH := func(t *testing.T) Handler {
		t.Helper()
		svc := loadRules(t, `
        default: allow
        rules:
          - action: deny
            path: /graphql
            graphql: {operations: [mutation], fields: [deleteRepository]}
`)
		return Build([]Filter{NewRules(svc, nil)}, upstreamOK)
	}
	t.Run("denies a fragment-hidden deleteRepository", func(t *testing.T) {
		req := httpReq(t, "POST", "https://api.github.com/graphql",
			[]byte(`{"query":"mutation { ...F } fragment F on Mutation { deleteRepository(input:{}) { clientMutationId } }"}`))
		tester(t, testCase{h: graphqlH(t), req: req, allow: false})
	})
	t.Run("fails closed on unparseable graphql", func(t *testing.T) {
		req := httpReq(t, "POST", "https://api.github.com/graphql", []byte(`{"query":"not graphql {"}`))
		tester(t, testCase{h: graphqlH(t), req: req, allow: false})
	})
	t.Run("allows a graphql query", func(t *testing.T) {
		req := httpReq(t, "POST", "https://api.github.com/graphql", []byte(`{"query":"{ viewer { login } }"}`))
		tester(t, testCase{h: graphqlH(t), req: req, allow: true})
	})
	t.Run("inspects a gzip-encoded graphql mutation", func(t *testing.T) {
		var zb bytes.Buffer
		zw := gzip.NewWriter(&zb)
		_, err := zw.Write([]byte(`{"query":"mutation { deleteRepository(input:{}) { clientMutationId } }"}`))
		require.NoError(t, err)
		err = zw.Close()
		require.NoError(t, err)
		req := httpReq(t, "POST", "https://api.github.com/graphql", zb.Bytes())
		req.Header.Set("Content-Encoding", "gzip")
		resp, err := graphqlH(t)(req)
		require.NoError(t, err)
		require.NotNil(t, resp.Denial, "gzip mutation not caught by the rule")
		assert.Contains(t, resp.Denial.Reason, "denied by")
	})

	githubRepo := func(t *testing.T) Handler {
		t.Helper()
		svc := loadRules(t, `
        rules:
          - action: allow
            github_repo: [octo/hello, octo/world]
`)
		return Build([]Filter{NewRules(svc, nil)}, upstreamOK)
	}
	t.Run("allows GET of octo/hello pulls", func(t *testing.T) {
		tester(t, testCase{h: githubRepo(t), req: httpReq(t, "GET", "https://api.github.com/repos/octo/hello/pulls", nil), allow: true})
	})
	t.Run("allows GET of octo/world issues", func(t *testing.T) {
		tester(t, testCase{h: githubRepo(t), req: httpReq(t, "GET", "https://api.github.com/repos/octo/world/issues", nil), allow: true})
	})
	t.Run("allows GET of a case-insensitive github repo", func(t *testing.T) {
		tester(t, testCase{h: githubRepo(t), req: httpReq(t, "GET", "https://ghe.corp/api/v3/repos/Octo/Hello", nil), allow: true})
	})
	t.Run("denies GET of a sibling repo name", func(t *testing.T) {
		tester(t, testCase{h: githubRepo(t), req: httpReq(t, "GET", "https://api.github.com/repos/octo/hello2", nil), allow: false})
	})
	t.Run("allows git upload-pack for octo/hello", func(t *testing.T) {
		tester(t, testCase{h: githubRepo(t), req: httpReq(t, "GET", "https://github.com/octo/hello.git/git-upload-pack", nil), allow: true})
	})
	t.Run("denies git receive-pack for another repo", func(t *testing.T) {
		tester(t, testCase{h: githubRepo(t), req: httpReq(t, "GET", "https://github.com/octo/other.git/git-receive-pack", nil), allow: false})
	})
	t.Run("denies GET by numeric repository id", func(t *testing.T) {
		tester(t, testCase{h: githubRepo(t), req: httpReq(t, "GET", "https://api.github.com/repositories/123/pulls", nil), allow: false})
	})
	t.Run("denies GET of user repos", func(t *testing.T) {
		tester(t, testCase{h: githubRepo(t), req: httpReq(t, "GET", "https://api.github.com/user/repos", nil), allow: false})
	})

	githubSub := func(t *testing.T) Handler {
		t.Helper()
		svc := loadRules(t, `
        rules:
          - action: allow
            methods: [GET]
            github_repo: [octo/hello]
            github_subpaths: ["", "pulls/**"]
          - action: allow
            methods: [PUT]
            github_repo: [octo/hello]
            github_subpaths: ["pulls/*/merge"]
`)
		return Build([]Filter{NewRules(svc, nil)}, upstreamOK)
	}
	t.Run("allows GET of the github repo root", func(t *testing.T) {
		tester(t, testCase{h: githubSub(t), req: httpReq(t, "GET", "https://api.github.com/repos/octo/hello", nil), allow: true})
	})
	t.Run("allows GET of repo pulls", func(t *testing.T) {
		tester(t, testCase{h: githubSub(t), req: httpReq(t, "GET", "https://api.github.com/repos/octo/hello/pulls", nil), allow: true})
	})
	t.Run("allows GET of pull comments", func(t *testing.T) {
		tester(t, testCase{h: githubSub(t), req: httpReq(t, "GET", "https://api.github.com/repos/octo/hello/pulls/1/comments", nil), allow: true})
	})
	t.Run("denies GET of repo issues", func(t *testing.T) {
		tester(t, testCase{h: githubSub(t), req: httpReq(t, "GET", "https://api.github.com/repos/octo/hello/issues", nil), allow: false})
	})
	t.Run("allows PUT merge of a pull", func(t *testing.T) {
		tester(t, testCase{h: githubSub(t), req: httpReq(t, "PUT", "https://api.github.com/repos/octo/hello/pulls/3/merge", nil), allow: true})
	})
	t.Run("denies git upload-pack when subpaths omit it", func(t *testing.T) {
		tester(t, testCase{h: githubSub(t), req: httpReq(t, "GET", "https://github.com/octo/hello.git/git-upload-pack", nil), allow: false})
	})
	t.Run("denies PUT merge on another repo", func(t *testing.T) {
		tester(t, testCase{h: githubSub(t), req: httpReq(t, "PUT", "https://api.github.com/repos/octo/other/pulls/3/merge", nil), allow: false})
	})

	t.Run("runs rule filters only on a matching allow", func(t *testing.T) {
		svc := loadRules(t, `
        rules:
          - action: allow
            path: /allowed
          - action: deny
            path: /denied
          - action: allow
            path: /other
`)
		var ran []string
		tag := func(name string) Filter {
			return filterFunc(func(req *Request, next Handler) (*Response, error) {
				ran = append(ran, name)
				return next(req)
			})
		}
		h := Build([]Filter{NewRules(svc, nil).WithRuleFilters([][]Filter{
			{tag("allowed")},
			{tag("denied")},
			{tag("other")},
		})}, upstreamOK)
		ran = nil
		resp, err := h(httpReq(t, "GET", "https://gitlab.com/allowed", nil))
		require.NoError(t, err)
		assert.Nil(t, resp.Denial)
		assert.Equal(t, []string{"allowed"}, ran)
		ran = nil
		resp, err = h(httpReq(t, "GET", "https://gitlab.com/denied", nil))
		require.NoError(t, err)
		assert.NotNil(t, resp.Denial)
		assert.Empty(t, ran)
		ran = nil
		resp, err = h(httpReq(t, "GET", "https://gitlab.com/other", nil))
		require.NoError(t, err)
		assert.Nil(t, resp.Denial)
		assert.Equal(t, []string{"other"}, ran)
		ran = nil
		resp, err = h(httpReq(t, "GET", "https://gitlab.com/nope", nil))
		require.NoError(t, err)
		assert.NotNil(t, resp.Denial)
		assert.Empty(t, ran)
	})
	t.Run("runs rule filters after ask yes and not after ask no", func(t *testing.T) {
		svc := loadRules(t, `
        rules:
          - action: ask
            methods: [PUT]
`)
		var ran int
		tag := filterFunc(func(req *Request, next Handler) (*Response, error) {
			ran++
			return next(req)
		})
		answer := false
		env := &Env{Approver: approverFunc(func(AskRequest) bool { return answer })}
		h := Build([]Filter{NewRules(svc, env).WithRuleFilters([][]Filter{{tag}})}, upstreamOK)
		resp, err := h(httpReq(t, "PUT", "https://gitlab.com/x", nil))
		require.NoError(t, err)
		assert.NotNil(t, resp.Denial)
		assert.Equal(t, 0, ran)
		answer = true
		resp, err = h(httpReq(t, "PUT", "https://gitlab.com/x", nil))
		require.NoError(t, err)
		assert.Nil(t, resp.Denial)
		assert.Equal(t, 1, ran)
	})
	t.Run("denies an ask rule after no and allows after yes", func(t *testing.T) {
		svc := loadRules(t, `
        rules:
          - action: ask
            prompt: merge?
            methods: [PUT]
`)
		answer := false
		var asked string
		env := &Env{Approver: approverFunc(func(a AskRequest) bool { asked = a.Prompt; return answer })}
		h := Build([]Filter{NewRules(svc, env)}, upstreamOK)
		resp, err := h(httpReq(t, "PUT", "https://gitlab.com/x", nil))
		require.NoError(t, err)
		assert.NotNil(t, resp.Denial)
		assert.Equal(t, "merge?", asked)
		answer = true
		resp, err = h(httpReq(t, "PUT", "https://gitlab.com/x", nil))
		require.NoError(t, err)
		assert.Nil(t, resp.Denial)
	})
	t.Run("denies when a filter panics", func(t *testing.T) {
		boom := filterFunc(func(*Request, Handler) (*Response, error) { panic("boom") })
		resp, err := Build([]Filter{boom}, upstreamOK)(httpReq(t, "GET", "https://x/", nil))
		require.NoError(t, err)
		assert.NotNil(t, resp.Denial)
	})
}

func TestCheckPath(t *testing.T) {
	type testCase struct {
		path string
		ok   bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		assert.Equal(t, tc.ok, CheckPath(tc.path) == nil, "ok")
	}

	t.Run("accepts a decoded api path", func(t *testing.T) {
		tester(t, testCase{path: "/api/v4/projects/x", ok: true})
	})
	t.Run("rejects parent directory segments", func(t *testing.T) {
		tester(t, testCase{path: "/a/../b", ok: false})
	})
	t.Run("rejects current directory segments", func(t *testing.T) {
		tester(t, testCase{path: "/a/./b", ok: false})
	})
	t.Run("rejects empty path segments", func(t *testing.T) {
		tester(t, testCase{path: "/a//b", ok: false})
	})
	t.Run("rejects a backslash", func(t *testing.T) {
		tester(t, testCase{path: "/a\\b", ok: false})
	})
	t.Run("rejects parent segments after a project", func(t *testing.T) {
		tester(t, testCase{path: "/api/v4/projects/a/../../", ok: false})
	})
}

func TestCheckMethod(t *testing.T) {
	type testCase struct {
		method string
		ok     bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		assert.Equal(t, tc.ok, CheckMethod(tc.method) == nil, "ok")
	}

	t.Run("accepts GET", func(t *testing.T) {
		tester(t, testCase{method: "GET", ok: true})
	})
	t.Run("accepts DELETE", func(t *testing.T) {
		tester(t, testCase{method: "DELETE", ok: true})
	})
	t.Run("accepts PROPFIND", func(t *testing.T) {
		tester(t, testCase{method: "PROPFIND", ok: true})
	})
	t.Run("rejects lowercase delete", func(t *testing.T) {
		tester(t, testCase{method: "delete", ok: false})
	})
	t.Run("rejects mixed-case Delete", func(t *testing.T) {
		tester(t, testCase{method: "Delete", ok: false})
	})
	t.Run("rejects a trailing space", func(t *testing.T) {
		tester(t, testCase{method: "GET ", ok: false})
	})
	t.Run("rejects an empty method", func(t *testing.T) {
		tester(t, testCase{method: "", ok: false})
	})
	t.Run("rejects M-SEARCH", func(t *testing.T) {
		tester(t, testCase{method: "M-SEARCH", ok: false})
	})
}

func TestCheckMethodOverride(t *testing.T) {
	type testCase struct {
		req *Request
		ok  bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		assert.Equal(t, tc.ok, CheckMethodOverride(tc.req) == nil, "ok")
	}

	form := func(body string) *Request {
		r := httpReq(t, "POST", "https://gitlab.com/api/v4/projects/1", []byte(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	t.Run("rejects an override header", func(t *testing.T) {
		hdr := httpReq(t, "POST", "https://gitlab.com/x", nil)
		hdr.Header.Set("X-HTTP-Method-Override", "DELETE")
		tester(t, testCase{req: hdr, ok: false})
	})
	t.Run("rejects an override query", func(t *testing.T) {
		tester(t, testCase{req: httpReq(t, "POST", "https://gitlab.com/x?_method=DELETE", nil), ok: false})
	})
	t.Run("rejects a form _method", func(t *testing.T) {
		tester(t, testCase{req: form("a=1&_method=DELETE"), ok: false})
	})
	t.Run("rejects a multipart _method", func(t *testing.T) {
		multi := httpReq(t, "POST", "https://gitlab.com/x", []byte("--b\r\nContent-Disposition: form-data; name=\"_method\"\r\n\r\nDELETE\r\n--b--"))
		multi.Header.Set("Content-Type", "multipart/mixed; boundary=b")
		tester(t, testCase{req: multi, ok: false})
	})
	t.Run("rejects a body _method without content type", func(t *testing.T) {
		r := httpReq(t, "POST", "https://gitlab.com/x", []byte("_method=DELETE"))
		tester(t, testCase{req: r, ok: false})
	})
	t.Run("rejects an odd content type", func(t *testing.T) {
		r := form("_method=DELETE")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded, text/plain")
		tester(t, testCase{req: r, ok: false})
	})
	t.Run("rejects a bracketed _method key", func(t *testing.T) {
		tester(t, testCase{req: form("%5B_method%5D=DELETE"), ok: false})
	})
	t.Run("rejects an encoded _method key", func(t *testing.T) {
		tester(t, testCase{req: form("%5Fmethod=DELETE"), ok: false})
	})
	t.Run("rejects an underscore override header", func(t *testing.T) {
		r := httpReq(t, "POST", "https://gitlab.com/x", nil)
		r.Header["X_http_method_override"] = []string{"DELETE"}
		tester(t, testCase{req: r, ok: false})
	})
	t.Run("accepts a plain form body", func(t *testing.T) {
		tester(t, testCase{req: form("title=hello&description=world"), ok: true})
	})
	t.Run("accepts a json body with _method", func(t *testing.T) {
		r := httpReq(t, "POST", "https://gitlab.com/x", []byte(`{"_method":"DELETE"}`))
		r.Header.Set("Content-Type", "application/json")
		tester(t, testCase{req: r, ok: true})
	})
	t.Run("does not consume the body", func(t *testing.T) {
		r := form("title=hello")
		_ = CheckMethodOverride(r)
		b, err := io.ReadAll(r.Body.Reader())
		require.NoError(t, err)
		assert.Equal(t, "title=hello", string(b))
	})
}

func TestGlob(t *testing.T) {
	type testCase struct {
		pat  string
		name string
		want bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		assert.Equal(t, tc.want, Glob(tc.pat, tc.name))
	}

	t.Run("matches an exact path", func(t *testing.T) {
		tester(t, testCase{pat: "/api/v4/user", name: "/api/v4/user", want: true})
	})
	t.Run("matches a single star segment", func(t *testing.T) {
		tester(t, testCase{pat: "/api/*/user", name: "/api/v4/user", want: true})
	})
	t.Run("matches a trailing double star", func(t *testing.T) {
		tester(t, testCase{pat: "/api/**", name: "/api/v4/user", want: true})
	})
	t.Run("matches a double star against the prefix path", func(t *testing.T) {
		tester(t, testCase{pat: "/api/**", name: "/api", want: true})
	})
	t.Run("matches a nested double star", func(t *testing.T) {
		tester(t, testCase{pat: "/api/**/user", name: "/api/v4/x/user", want: true})
	})
	t.Run("matches a single star ref glob", func(t *testing.T) {
		tester(t, testCase{pat: "refs/heads/release/*", name: "refs/heads/release/1.0", want: true})
	})
	t.Run("does not let a single star cross a slash", func(t *testing.T) {
		tester(t, testCase{pat: "refs/heads/release/*", name: "refs/heads/release/1.0/hotfix", want: false})
	})
	t.Run("does not match a different ref prefix", func(t *testing.T) {
		tester(t, testCase{pat: "refs/heads/*", name: "refs/tags/v1", want: false})
	})
}

package chain

import (
	"context"
	"strings"
	"testing"

	"github.com/pastdev/agentcon/internal/bouncer/gitproto"
)

func TestDescribe(t *testing.T) {
	oidA := strings.Repeat("a", 40)
	oidB := strings.Repeat("b", 40)
	push := func(ups ...gitproto.RefUpdate) []byte {
		return gitproto.BuildPush(ups, nil, nil)
	}
	sshGit := func(cmd string, body []byte) *Request {
		req := &Request{
			Ctx:       context.Background(),
			Transport: TransportSSH,
			SSH:       &SSHInfo{Host: "github.com", User: "git", Kind: "git", Command: cmd},
		}
		if body != nil {
			req.Body = BytesBody(body)
		}
		return req
	}
	tester := func(t *testing.T, req *Request, want string) {
		t.Helper()
		got := req.Describe()
		if got != want {
			t.Errorf("got %q want %q", got, want)
		}
	}

	t.Run("describes an ssh git command without a push body", func(t *testing.T) {
		tester(t, sshGit("git-receive-pack 'pastdev/agentcon.git'", nil),
			"ssh git@github.com git: git-receive-pack 'pastdev/agentcon.git'")
	})
	t.Run("includes a tag create on an ssh receive-pack", func(t *testing.T) {
		body := push(gitproto.RefUpdate{OldOID: gitproto.ZeroOID, NewOID: oidB, Ref: "refs/tags/v0.1.1-ask-test"})
		tester(t, sshGit("git-receive-pack 'pastdev/agentcon.git'", body),
			"ssh git@github.com git: git-receive-pack 'pastdev/agentcon.git' create refs/tags/v0.1.1-ask-test")
	})
	t.Run("includes a tag delete on an ssh receive-pack", func(t *testing.T) {
		body := push(gitproto.RefUpdate{OldOID: oidA, NewOID: gitproto.ZeroOID, Ref: "refs/tags/v0.1.1-ask-test"})
		tester(t, sshGit("git-receive-pack 'pastdev/agentcon.git'", body),
			"ssh git@github.com git: git-receive-pack 'pastdev/agentcon.git' delete refs/tags/v0.1.1-ask-test")
	})
	t.Run("includes several ref updates", func(t *testing.T) {
		body := push(
			gitproto.RefUpdate{OldOID: oidA, NewOID: oidB, Ref: "refs/heads/feature"},
			gitproto.RefUpdate{OldOID: gitproto.ZeroOID, NewOID: oidB, Ref: "refs/tags/v0.1.0"},
		)
		tester(t, sshGit("git-receive-pack 'pastdev/agentcon.git'", body),
			"ssh git@github.com git: git-receive-pack 'pastdev/agentcon.git' update refs/heads/feature, create refs/tags/v0.1.0")
	})
	t.Run("describes an http path", func(t *testing.T) {
		tester(t, httpReq(t, "GET", "https://api.github.com/user", nil), "GET api.github.com/user")
	})
	t.Run("includes a tag create on an http receive-pack", func(t *testing.T) {
		body := push(gitproto.RefUpdate{OldOID: gitproto.ZeroOID, NewOID: oidB, Ref: "refs/tags/v0.1.0"})
		req := httpReq(t, "POST", "https://github.com/pastdev/agentcon.git/git-receive-pack", body)
		tester(t, req, "POST github.com/pastdev/agentcon.git/git-receive-pack create refs/tags/v0.1.0")
	})
	t.Run("does not inspect an http receive-pack advertisement", func(t *testing.T) {
		req := httpReq(t, "GET", "https://github.com/pastdev/agentcon.git/info/refs?service=git-receive-pack", nil)
		tester(t, req, "GET github.com/pastdev/agentcon.git/info/refs?service=git-receive-pack")
	})
	t.Run("includes a graphql merge mutation", func(t *testing.T) {
		req := httpReq(t, "POST", "https://api.github.com/graphql",
			[]byte(`{"query":"mutation { mergePullRequest(input:{pullRequestId:\"x\"}) { clientMutationId } }"}`))
		tester(t, req, "POST api.github.com/graphql mutation mergePullRequest")
	})
}

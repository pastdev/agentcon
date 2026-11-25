package gitsign

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeRemote(t *testing.T) {
	type testCase struct {
		in      string
		want    string
		wantErr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got, err := NormalizeRemote(tc.in)
		if tc.wantErr != "" {
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			return
		}
		require.NoError(t, err)
		assert.Equal(t, tc.want, got)
	}

	t.Run("https", func(t *testing.T) {
		tester(t, testCase{in: "https://github.com/pastdev/agentcon.git", want: "github.com/pastdev/agentcon"})
	})
	t.Run("http without .git", func(t *testing.T) {
		tester(t, testCase{in: "http://github.com/pastdev/agentcon", want: "github.com/pastdev/agentcon"})
	})
	t.Run("ssh url", func(t *testing.T) {
		tester(t, testCase{in: "ssh://git@github.com/pastdev/agentcon.git", want: "github.com/pastdev/agentcon"})
	})
	t.Run("ssh url with port", func(t *testing.T) {
		tester(t, testCase{in: "ssh://git@github.com:22/pastdev/agentcon.git", want: "github.com/pastdev/agentcon"})
	})
	t.Run("scp-like", func(t *testing.T) {
		tester(t, testCase{in: "git@github.com:pastdev/agentcon.git", want: "github.com/pastdev/agentcon"})
	})
	t.Run("scp-like without user", func(t *testing.T) {
		tester(t, testCase{in: "github.com:pastdev/agentcon", want: "github.com/pastdev/agentcon"})
	})
	t.Run("host lowercased, path case kept", func(t *testing.T) {
		tester(t, testCase{in: "git@GitHub.Com:PastDev/Agentcon.git", want: "github.com/PastDev/Agentcon"})
	})
	t.Run("gitlab subgroup", func(t *testing.T) {
		tester(t, testCase{in: "https://gitlab.example.com/group/sub/project.git", want: "gitlab.example.com/group/sub/project"})
	})
	t.Run("credentials in https url are dropped", func(t *testing.T) {
		tester(t, testCase{in: "https://x-access-token:secret@github.com/pastdev/agentcon.git", want: "github.com/pastdev/agentcon"}) //nolint:gosec // fake credential in a test fixture
	})
	t.Run("dot segments are cleaned", func(t *testing.T) {
		tester(t, testCase{in: "https://github.com/pastdev/../pastdev/./agentcon.git/", want: "github.com/pastdev/agentcon"})
	})
	t.Run("query", func(t *testing.T) {
		tester(t, testCase{in: "https://github.com/pastdev/agentcon?x=1", wantErr: "must not have a query"})
	})
	t.Run("fragment", func(t *testing.T) {
		tester(t, testCase{in: "https://github.com/pastdev/agentcon#x", wantErr: "must not have a fragment"})
	})
	t.Run("empty", func(t *testing.T) {
		tester(t, testCase{in: " ", wantErr: "empty"})
	})
	t.Run("missing path", func(t *testing.T) {
		tester(t, testCase{in: "https://github.com/", wantErr: "missing path"})
	})
	t.Run("local path", func(t *testing.T) {
		tester(t, testCase{in: "/srv/git/repo.git", wantErr: "not a url or host:path"})
	})
}

func TestParseArgs(t *testing.T) {
	type testCase struct {
		args    []string
		want    Args
		wantErr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got, err := ParseArgs(tc.args)
		if tc.wantErr != "" {
			require.ErrorIs(t, err, ErrUsage)
			assert.Contains(t, err.Error(), tc.wantErr)
			return
		}
		require.NoError(t, err)
		tc.want.Raw = got.Raw
		assert.Equal(t, tc.want, got)
	}

	t.Run("git sign", func(t *testing.T) {
		tester(t, testCase{args: []string{"--status-fd=2", "-bsau", "7C44826B7B1878A0"}, want: Args{Mode: ModeSign, StatusFD: 2, Key: "7C44826B7B1878A0"}})
	})
	t.Run("separate flags", func(t *testing.T) {
		tester(t, testCase{args: []string{"--status-fd", "3", "--detach-sign", "--armor", "--local-user", "K"}, want: Args{Mode: ModeSign, StatusFD: 3, Key: "K"}})
	})
	t.Run("dry run", func(t *testing.T) {
		tester(t, testCase{args: []string{"--dry-run", "-bsau", "K"}, want: Args{Mode: ModeSign, StatusFD: -1, Key: "K", DryRun: true}})
	})
	t.Run("git verify", func(t *testing.T) {
		tester(t, testCase{args: []string{"--keyid-format=long", "--status-fd=1", "--verify", "/tmp/sig", "-"}, want: Args{Mode: ModeVerify, StatusFD: 1}})
	})
	t.Run("help", func(t *testing.T) {
		tester(t, testCase{args: []string{"--help"}, want: Args{Mode: ModeHelp}})
	})
	t.Run("clearsign is refused", func(t *testing.T) {
		tester(t, testCase{args: []string{"--clearsign", "-u", "K"}, wantErr: `unsupported argument "--clearsign"`})
	})
	t.Run("inline sign is refused", func(t *testing.T) {
		tester(t, testCase{args: []string{"-sau", "K"}, wantErr: "only detached signing"})
	})
	t.Run("missing key", func(t *testing.T) {
		tester(t, testCase{args: []string{"-bsa"}, wantErr: "signing key"})
	})
	t.Run("u not last", func(t *testing.T) {
		tester(t, testCase{args: []string{"-bus", "K"}, wantErr: "-u must end"})
	})
	t.Run("u without value", func(t *testing.T) {
		tester(t, testCase{args: []string{"-bsau"}, wantErr: "needs a value"})
	})
	t.Run("encrypt is refused", func(t *testing.T) {
		tester(t, testCase{args: []string{"-e"}, wantErr: "unsupported option -e"})
	})
}

func fakeGit(values map[string]string) GitRunner {
	return func(_ context.Context, args ...string) (string, error) {
		v, ok := values[strings.Join(args, " ")]
		if !ok {
			return "", errors.New("exit status 1")
		}
		return v, nil
	}
}

func TestRepository(t *testing.T) {
	type testCase struct {
		git  map[string]string
		want string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		assert.Equal(t, tc.want, Repository(t.Context(), fakeGit(tc.git)))
	}

	t.Run("config override wins", func(t *testing.T) {
		tester(t, testCase{git: map[string]string{
			"config --get agentcon.signing.repository": "gitlab.example.com/group/project",
			"remote get-url origin":                    "git@github.com:pastdev/agentcon.git",
		}, want: "gitlab.example.com/group/project"})
	})
	t.Run("origin remote", func(t *testing.T) {
		tester(t, testCase{git: map[string]string{"remote get-url origin": "git@github.com:pastdev/agentcon.git"}, want: "github.com/pastdev/agentcon"})
	})
	t.Run("no origin", func(t *testing.T) {
		tester(t, testCase{git: map[string]string{}, want: ""})
	})
	t.Run("unparsable origin", func(t *testing.T) {
		tester(t, testCase{git: map[string]string{"remote get-url origin": "/srv/repo.git"}, want: ""})
	})
}

func TestRunMain(t *testing.T) {
	type testCase struct {
		args       []string
		env        map[string]string
		status     int
		body       string
		headers    map[string]string
		wantCode   int
		wantStdout string
		wantStatus string
		wantStderr string
		wantSent   bool
		wantQuery  string
	}
	okHeaders := map[string]string{
		"X-Bouncer-Signer-Fingerprint":   "ABCDEF",
		"X-Bouncer-Signer-Key-Algorithm": "22",
		"X-Bouncer-Signer-Hash":          "8",
		"X-Bouncer-Signer-Created":       "1764000000",
		"X-Bouncer-Signer-Type":          "commit",
	}
	const sig = "-----BEGIN PGP SIGNATURE-----\nx\n-----END PGP SIGNATURE-----\n"
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		var sent bool
		var query, gotBody string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sent = true
			query = r.URL.RawQuery
			b, _ := io.ReadAll(r.Body)
			gotBody = string(b)
			for k, v := range tc.headers {
				w.Header().Set(k, v)
			}
			w.WriteHeader(tc.status)
			_, _ = io.WriteString(w, tc.body)
		}))
		t.Cleanup(srv.Close)
		env := map[string]string{EnvSignerURL: srv.URL + "/openpgp/sign"}
		for k, v := range tc.env {
			env[k] = v
		}
		var stdout, stderr, status bytes.Buffer
		code := Main(t.Context(), tc.args, IO{
			Stdin:  strings.NewReader("tree x\n\nmsg\n"),
			Stdout: &stdout,
			Stderr: &stderr,
			Getenv: func(k string) string { return env[k] },
			Status: func(fd int) (io.Writer, error) {
				if fd != 2 {
					return nil, errors.New("bad fd")
				}
				return &status, nil
			},
			Git:    fakeGit(map[string]string{"remote get-url origin": "git@github.com:pastdev/agentcon.git"}),
			Client: srv.Client(),
			Verify: func(context.Context, []string) (int, error) { return 7, nil },
		})
		assert.Equal(t, tc.wantCode, code, stderr.String())
		assert.Equal(t, tc.wantStdout, stdout.String())
		assert.Equal(t, tc.wantStatus, status.String())
		assert.Contains(t, stderr.String(), tc.wantStderr)
		assert.Equal(t, tc.wantSent, sent)
		if tc.wantSent {
			assert.Equal(t, tc.wantQuery, query)
			assert.Equal(t, "tree x\n\nmsg\n", gotBody)
		}
	}
	signArgs := []string{"--status-fd=2", "-bsau", "C26E02CE599B53FF"}

	t.Run("signs and writes status", func(t *testing.T) {
		tester(t, testCase{
			args: signArgs, status: 200, body: sig, headers: okHeaders,
			wantCode: 0, wantStdout: sig,
			wantStatus: "[GNUPG:] BEGIN_SIGNING H8\n[GNUPG:] SIG_CREATED D 22 8 00 1764000000 ABCDEF\n",
			wantStderr: "bouncer: signed commit for github.com/pastdev/agentcon with C26E02CE599B53FF via 127.0.0.1",
			wantSent:   true, wantQuery: "key=C26E02CE599B53FF&repository=github.com%2Fpastdev%2Fagentcon",
		})
	})
	t.Run("relays a denial and exits 1", func(t *testing.T) {
		tester(t, testCase{
			args: signArgs, status: 403, body: "agent-bouncer: request denied by filter:signing-repository-scope: repository not claimed\n",
			wantCode: 1, wantStderr: "bouncer: signer answered 403: agent-bouncer: request denied by filter:signing-repository-scope: repository not claimed",
			wantSent: true, wantQuery: "key=C26E02CE599B53FF&repository=github.com%2Fpastdev%2Fagentcon",
		})
	})
	t.Run("refuses a non-signature 200", func(t *testing.T) {
		tester(t, testCase{
			args: signArgs, status: 200, body: "<html>", headers: okHeaders,
			wantCode: 1, wantStderr: "not an armored signature", wantSent: true,
			wantQuery: "key=C26E02CE599B53FF&repository=github.com%2Fpastdev%2Fagentcon",
		})
	})
	t.Run("dry run sends nothing", func(t *testing.T) {
		tester(t, testCase{
			args: append([]string{"--dry-run"}, signArgs...), wantCode: 0,
			wantStderr: "repository: github.com/pastdev/agentcon\nkey: C26E02CE599B53FF\nsha256: ",
		})
	})
	t.Run("missing signer url", func(t *testing.T) {
		tester(t, testCase{
			args: signArgs, env: map[string]string{EnvSignerURL: ""}, wantCode: 1,
			wantStderr: "BOUNCER_SIGNER_URL is not set",
		})
	})
	t.Run("plain http signer url", func(t *testing.T) {
		tester(t, testCase{
			args: signArgs, env: map[string]string{EnvSignerURL: "http://signer.bouncer.internal/openpgp/sign"}, wantCode: 1,
			wantStderr: "want https://host/path",
		})
	})
	t.Run("verify defers to gpg", func(t *testing.T) {
		tester(t, testCase{args: []string{"--status-fd=1", "--verify", "sig", "-"}, wantCode: 7})
	})
	t.Run("usage error exits 2", func(t *testing.T) {
		tester(t, testCase{args: []string{"-e"}, wantCode: 2, wantStderr: "unsupported option -e"})
	})
}

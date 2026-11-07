package envexport

import (
	"testing"
)

func TestBuild(t *testing.T) {
	type testCase struct {
		params Params
		want   map[string]string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got := Build(tc.params)
		have := map[string]string{}
		for _, kv := range got.Vars {
			have[kv[0]] = kv[1]
		}
		for k, v := range tc.want {
			if have[k] != v {
				t.Fatalf("%s=%q, want %q", k, have[k], v)
			}
		}
	}

	t.Run("exports proxy, ca, ssh, and placeholder vars", func(t *testing.T) {
		tester(t, testCase{
			params: Params{
				ProxyAddr:    "127.0.0.1:8228",
				SSHAddr:      "127.0.0.1:8229",
				Token:        "t0k'x",
				SessionID:    "abcd",
				CACert:       "/s/ca.pem",
				CABundle:     "/s/ca-bundle.pem",
				SSHCommand:   `"/usr/bin/ssh" -F "/s/ssh/config"`,
				Placeholders: map[string]string{"GITLAB_TOKEN": "bouncer-placeholder-gitlab"},
			},
			want: map[string]string{
				"HTTPS_PROXY":         "http://bouncer:t0k%27x@127.0.0.1:8228",
				"SSL_CERT_FILE":       "/s/ca-bundle.pem",
				"NODE_EXTRA_CA_CERTS": "/s/ca.pem",
				"GIT_SSH_COMMAND":     `"/usr/bin/ssh" -F "/s/ssh/config"`,
				"BOUNCER_SESSION":     "t0k'x",
				"BOUNCER_SSH_ADDR":    "127.0.0.1:8229",
				"GITLAB_TOKEN":        "bouncer-placeholder-gitlab",
			},
		})
	})
}

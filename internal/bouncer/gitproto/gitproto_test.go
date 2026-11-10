package gitproto

import (
	"bytes"
	"io"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const a = "1111111111111111111111111111111111111111"
const b = "2222222222222222222222222222222222222222"

func TestParsePush(t *testing.T) {
	type testCase struct {
		body         []byte
		wantUpdates  int
		wantTypes    []string
		wantCap      string
		wantOption   string
		wantRef      string
		wantSigned   bool
		wantErr      bool
		wantPackRest bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		r := bytes.NewReader(tc.body)
		p, err := ParsePush(r)
		if tc.wantErr {
			require.Error(t, err)
			return
		}
		require.NoError(t, err)
		if tc.wantUpdates != 0 {
			require.Len(t, p.Updates, tc.wantUpdates)
		}
		for i, want := range tc.wantTypes {
			assert.Equal(t, want, p.Updates[i].Type, "update %d", i)
		}
		if tc.wantCap != "" {
			assert.True(t, p.HasCapability(tc.wantCap), "caps: %+v", p)
		}
		if tc.wantOption != "" {
			assert.Equal(t, []string{tc.wantOption}, p.PushOptions)
		}
		if tc.wantRef != "" {
			assert.Equal(t, tc.wantRef, p.Updates[len(p.Updates)-1].Ref, "last ref")
		}
		if tc.wantSigned {
			assert.True(t, p.Signed, "signed")
			require.Len(t, p.Updates, 1)
			assert.Equal(t, "refs/heads/main", p.Updates[0].Ref)
		}
		if tc.wantPackRest {
			rest, err := io.ReadAll(r)
			require.NoError(t, err)
			assert.True(t, bytes.HasPrefix(rest, []byte("PACK")), "parser consumed packfile; rest=%q", rest)
		}
	}

	t.Run("parses create, update, and delete commands", func(t *testing.T) {
		body := BuildPush([]RefUpdate{
			{OldOID: a, NewOID: b, Ref: "refs/heads/main"},
			{OldOID: ZeroOID, NewOID: b, Ref: "refs/heads/feature"},
			{OldOID: a, NewOID: ZeroOID, Ref: "refs/heads/old"},
		}, []string{"report-status", "side-band-64k"}, []string{"ci.skip"})
		tester(t, testCase{
			body:         body,
			wantUpdates:  3,
			wantTypes:    []string{UpdateUpdate, UpdateCreate, UpdateDelete},
			wantCap:      "report-status",
			wantOption:   "ci.skip",
			wantPackRest: true,
		})
	})
	t.Run("parses many refs beyond 100 bytes", func(t *testing.T) {
		var ups []RefUpdate
		for i := 0; i < 50; i++ {
			ups = append(ups, RefUpdate{OldOID: a, NewOID: b, Ref: "refs/heads/branch-" + strings.Repeat("x", i)})
		}
		ups = append(ups, RefUpdate{OldOID: a, NewOID: b, Ref: "refs/heads/foo"})
		tester(t, testCase{
			body:    BuildPush(ups, nil, nil),
			wantRef: "refs/heads/foo",
		})
	})
	t.Run("parses a signed push certificate", func(t *testing.T) {
		var buf bytes.Buffer
		for _, l := range []string{
			"push-cert\x00report-status\n", "certificate version 0.1\n", "pusher A <a@x> 1 +0000\n", "\n",
			a + " " + b + " refs/heads/main\n", "-----BEGIN PGP SIGNATURE-----\n", "sig\n", "-----END PGP SIGNATURE-----\n",
			"push-cert-end\n",
		} {
			buf.Write(EncodePkt(l))
		}
		buf.Write(Flush)
		tester(t, testCase{body: buf.Bytes(), wantSigned: true})
	})
	t.Run("rejects a malformed command", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write(EncodePkt("garbage\n"))
		buf.Write(Flush)
		tester(t, testCase{body: buf.Bytes(), wantErr: true})
	})
	t.Run("rejects a bad pkt length", func(t *testing.T) {
		tester(t, testCase{body: []byte("zzzz"), wantErr: true})
	})
	t.Run("attaches capabilities after shallow lines", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write(EncodePkt("shallow " + a + "\n"))
		buf.Write(EncodePkt(a + " " + b + " refs/heads/main\x00report-status side-band-64k\n"))
		buf.Write(Flush)
		tester(t, testCase{
			body:        buf.Bytes(),
			wantUpdates: 1,
			wantRef:     "refs/heads/main",
			wantCap:     "report-status",
		})
	})
	t.Run("rejects a ref with an embedded nul", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write(EncodePkt(a + " " + b + " refs/heads/ok\x00report-status\n"))
		buf.Write(EncodePkt(a + " " + b + " refs/heads/main\x00x\n"))
		buf.Write(Flush)
		tester(t, testCase{body: buf.Bytes(), wantErr: true})
	})
	t.Run("rejects a ref with a space", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write(EncodePkt(a + " " + b + " refs/heads/ok\x00report-status\n"))
		buf.Write(EncodePkt(a + " " + b + " refs/heads/a b\n"))
		buf.Write(Flush)
		tester(t, testCase{body: buf.Bytes(), wantErr: true})
	})
	t.Run("rejects a ref with double dots", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write(EncodePkt(a + " " + b + " refs/heads/ok\x00report-status\n"))
		buf.Write(EncodePkt(a + " " + b + " refs/heads/a..b\n"))
		buf.Write(Flush)
		tester(t, testCase{body: buf.Bytes(), wantErr: true})
	})
	t.Run("rejects a ref without a refs prefix", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write(EncodePkt(a + " " + b + " refs/heads/ok\x00report-status\n"))
		buf.Write(EncodePkt(a + " " + b + " main\n"))
		buf.Write(Flush)
		tester(t, testCase{body: buf.Bytes(), wantErr: true})
	})
	t.Run("rejects a ref with an embedded newline", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write(EncodePkt(a + " " + b + " refs/heads/ok\x00report-status\n"))
		buf.Write(EncodePkt(a + " " + b + " refs/heads/x\n0000\n"))
		buf.Write(Flush)
		tester(t, testCase{body: buf.Bytes(), wantErr: true})
	})
}

func TestFromHTTP(t *testing.T) {
	type testCase struct {
		path      string
		query     string
		wantSvc   string
		wantRepo  string
		wantNotOK bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		q, err := url.ParseQuery(tc.query)
		require.NoError(t, err)
		info, ok := FromHTTP(tc.path, q)
		if tc.wantNotOK {
			assert.False(t, ok, "non-git path recognized")
			return
		}
		require.True(t, ok, "ok")
		assert.Equal(t, &Info{Service: tc.wantSvc, Repo: tc.wantRepo}, info)
	}

	t.Run("parses receive-pack info/refs", func(t *testing.T) {
		tester(t, testCase{path: "/group/proj.git/info/refs", query: "service=git-receive-pack", wantSvc: ServiceReceivePack, wantRepo: "group/proj"})
	})
	t.Run("parses upload-pack on a nested repo", func(t *testing.T) {
		tester(t, testCase{path: "/group/sub/proj.git/git-upload-pack", wantSvc: ServiceUploadPack, wantRepo: "group/sub/proj"})
	})
	t.Run("parses receive-pack without a git suffix", func(t *testing.T) {
		tester(t, testCase{path: "/group/proj/git-receive-pack", wantSvc: ServiceReceivePack, wantRepo: "group/proj"})
	})
	t.Run("parses lfs batch", func(t *testing.T) {
		tester(t, testCase{path: "/group/proj.git/info/lfs/objects/batch", wantSvc: ServiceLFS, wantRepo: "group/proj"})
	})
	t.Run("ignores a non-git path", func(t *testing.T) {
		tester(t, testCase{path: "/api/v4/projects", wantNotOK: true})
	})
}

func TestFromSSHCommand(t *testing.T) {
	type testCase struct {
		cmd      string
		wantSvc  string
		wantRepo string
		wantBad  bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		info, ok := FromSSHCommand(tc.cmd)
		if tc.wantBad {
			assert.False(t, ok, "accepted %q", tc.cmd)
			return
		}
		require.True(t, ok, "ok")
		if tc.wantSvc != "" {
			assert.Equal(t, tc.wantSvc, info.Service)
		}
		assert.Equal(t, tc.wantRepo, info.Repo)
	}

	t.Run("parses git-receive-pack", func(t *testing.T) {
		tester(t, testCase{cmd: "git-receive-pack '/group/proj.git'", wantSvc: ServiceReceivePack, wantRepo: "group/proj"})
	})
	t.Run("parses git upload-pack", func(t *testing.T) {
		tester(t, testCase{cmd: "git upload-pack 'proj.git'", wantSvc: ServiceUploadPack, wantRepo: "proj"})
	})
	t.Run("parses git-upload-pack", func(t *testing.T) {
		tester(t, testCase{cmd: "git-upload-pack '/owner/repo.git'", wantRepo: "owner/repo"})
	})
	t.Run("rejects a command with a trailing shell", func(t *testing.T) {
		tester(t, testCase{cmd: "git-receive-pack 'a.git'; rm -rf ~", wantBad: true})
	})
	t.Run("rejects a command with a shell and", func(t *testing.T) {
		tester(t, testCase{cmd: "git-receive-pack a.git && x", wantBad: true})
	})
	t.Run("rejects a non-git command", func(t *testing.T) {
		tester(t, testCase{cmd: "ls", wantBad: true})
	})
	t.Run("rejects a broken quote", func(t *testing.T) {
		tester(t, testCase{cmd: "git-receive-pack 'a'b'", wantBad: true})
	})
	t.Run("rejects a newline redirect", func(t *testing.T) {
		tester(t, testCase{cmd: "git-upload-pack repo\n>/tmp/x", wantBad: true})
	})
	t.Run("rejects a quoted newline", func(t *testing.T) {
		tester(t, testCase{cmd: "git-upload-pack 'repo\nx'", wantBad: true})
	})
	t.Run("rejects a redirect", func(t *testing.T) {
		tester(t, testCase{cmd: "git-upload-pack repo>/tmp/x", wantBad: true})
	})
	t.Run("rejects a home-relative path", func(t *testing.T) {
		tester(t, testCase{cmd: "git-upload-pack ~victim/secret", wantBad: true})
	})
	t.Run("rejects a parent path", func(t *testing.T) {
		tester(t, testCase{cmd: "git-receive-pack 'org/allowed.git/../other'", wantBad: true})
	})
	t.Run("rejects a double-slash path", func(t *testing.T) {
		tester(t, testCase{cmd: "git-upload-pack '//x'", wantBad: true})
	})
	t.Run("rejects a leading space", func(t *testing.T) {
		tester(t, testCase{cmd: " git-upload-pack 'a'", wantBad: true})
	})
	t.Run("rejects extra spaces before the repo", func(t *testing.T) {
		tester(t, testCase{cmd: "git-upload-pack  'a'", wantBad: true})
	})
	t.Run("rejects a trailing space", func(t *testing.T) {
		tester(t, testCase{cmd: "git-upload-pack 'a' ", wantBad: true})
	})
	t.Run("rejects a glob in the repo", func(t *testing.T) {
		tester(t, testCase{cmd: "git-upload-pack 'a*'", wantBad: true})
	})
	t.Run("rejects an empty repo", func(t *testing.T) {
		tester(t, testCase{cmd: "git-upload-pack ''", wantBad: true})
	})
}

func TestRejectPush(t *testing.T) {
	type testCase struct {
		p           *Push
		reason      string
		wantNil     bool
		wantBand2   string
		wantBand1Ng string
		wantUnpack  string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		out := RejectPush(tc.p, tc.reason)
		if tc.wantNil {
			assert.Nil(t, out, "no report-status capability should yield nil")
			return
		}
		r := bytes.NewReader(out)
		var bands [3][]byte
		for {
			payload, special, err := ReadPkt(r)
			require.NoError(t, err)
			if special == "flush" {
				break
			}
			bands[payload[0]] = append(bands[payload[0]], payload[1:]...)
		}
		assert.Equal(t, tc.wantBand2, string(bands[2]))
		assert.Contains(t, string(bands[1]), tc.wantBand1Ng)
		assert.Contains(t, string(bands[1]), tc.wantUnpack)
	}

	t.Run("writes a sideband status report", func(t *testing.T) {
		tester(t, testCase{
			p:           &Push{Updates: []RefUpdate{{Ref: "refs/heads/main"}}, Capabilities: []string{"report-status", "side-band-64k"}},
			reason:      "nope\nreally",
			wantBand2:   "agent-bouncer: nope really\n",
			wantBand1Ng: "ng refs/heads/main nope really\n",
			wantUnpack:  "unpack ok",
		})
	})
	t.Run("returns nil without report-status", func(t *testing.T) {
		tester(t, testCase{
			p:       &Push{Updates: []RefUpdate{{Ref: "refs/heads/main"}}},
			reason:  "x",
			wantNil: true,
		})
	})
}

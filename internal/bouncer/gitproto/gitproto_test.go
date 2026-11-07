package gitproto

import (
	"bytes"
	"io"
	"net/url"
	"strings"
	"testing"
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
			if err == nil {
				t.Fatal("expected error")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if tc.wantUpdates != 0 && len(p.Updates) != tc.wantUpdates {
			t.Fatalf("updates: %+v", p.Updates)
		}
		for i, want := range tc.wantTypes {
			if p.Updates[i].Type != want {
				t.Errorf("update %d type %s, want %s", i, p.Updates[i].Type, want)
			}
		}
		if tc.wantCap != "" && !p.HasCapability(tc.wantCap) {
			t.Errorf("caps/options: %+v", p)
		}
		if tc.wantOption != "" && (len(p.PushOptions) != 1 || p.PushOptions[0] != tc.wantOption) {
			t.Errorf("caps/options: %+v", p)
		}
		if tc.wantRef != "" {
			if p.Updates[len(p.Updates)-1].Ref != tc.wantRef {
				t.Fatal("last ref not parsed")
			}
		}
		if tc.wantSigned && (!p.Signed || len(p.Updates) != 1 || p.Updates[0].Ref != "refs/heads/main") {
			t.Fatalf("%+v", p)
		}
		if tc.wantPackRest {
			rest, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(rest, []byte("PACK")) {
				t.Errorf("parser consumed packfile; rest=%q", rest)
			}
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
		wantOK    bool
		wantNotOK bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		q, err := url.ParseQuery(tc.query)
		if err != nil {
			t.Fatal(err)
		}
		info, ok := FromHTTP(tc.path, q)
		if tc.wantNotOK {
			if ok {
				t.Error("non-git path recognized")
			}
			return
		}
		if !ok || info.Service != tc.wantSvc || info.Repo != tc.wantRepo {
			t.Errorf("FromHTTP(%q) = %+v, %v", tc.path, info, ok)
		}
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
		wantOK   bool
		wantBad  bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		info, ok := FromSSHCommand(tc.cmd)
		if tc.wantBad {
			if ok {
				t.Errorf("accepted %q", tc.cmd)
			}
			return
		}
		if !ok || (tc.wantSvc != "" && info.Service != tc.wantSvc) || info.Repo != tc.wantRepo {
			t.Fatalf("%+v %v", info, ok)
		}
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
			if out != nil {
				t.Fatal("no report-status capability should yield nil")
			}
			return
		}
		r := bytes.NewReader(out)
		var bands [3][]byte
		for {
			payload, special, err := ReadPkt(r)
			if err != nil {
				t.Fatal(err)
			}
			if special == "flush" {
				break
			}
			bands[payload[0]] = append(bands[payload[0]], payload[1:]...)
		}
		if string(bands[2]) != tc.wantBand2 {
			t.Fatalf("band 2: %q", bands[2])
		}
		if !bytes.Contains(bands[1], []byte(tc.wantBand1Ng)) || !bytes.Contains(bands[1], []byte(tc.wantUnpack)) {
			t.Fatalf("band 1: %q", bands[1])
		}
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

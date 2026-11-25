//go:build issue40

// Bitwarden mode signs with real OpenPGP keys held in Bitwarden items, each
// with the armored key in its notes and the passphrase in a custom field
// named password. The sidecar unlocks the vault itself, and its master
// password and verification code prompts are answered at this terminal, as
// agentcon run does. Nothing secret is written to disk or printed.
//
//	go run -tags issue40 ./ad_hoc/issue-40/smoke -agentcon /tmp/agentcon \
//	  -bitwarden-email agent@example.com -public-keys pub.asc \
//	  -key gpg-key-a=<fingerprint> -key gpg-key-b=<fingerprint>
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pastdev/agentcon/pkg/bouncer/config"
	"github.com/pastdev/agentcon/pkg/bouncer/host"
	"github.com/pastdev/agentcon/pkg/bouncer/mgmt"
)

type itemKey struct {
	item, fpr string
}

type keyFlags []itemKey

func (k *keyFlags) String() string { return fmt.Sprint(*k) }

func (k *keyFlags) Set(v string) error {
	item, fpr, ok := strings.Cut(v, "=")
	if !ok || item == "" {
		return fmt.Errorf("want <item>=<fingerprint>, got %q", v)
	}
	id, err := config.NormalizeKeyID(fpr)
	if err != nil {
		return err //nolint:wrapcheck // flag package adds context
	}
	if len(id) != 40 && len(id) != 64 {
		return fmt.Errorf("%s: want a full fingerprint, so git log %%GF can be compared", item)
	}
	*k = append(*k, itemKey{item: item, fpr: id})
	return nil
}

func runBitwarden(bin, email, pubsPath string, keys keyFlags) error {
	if bin == "" || pubsPath == "" || len(keys) == 0 {
		return errors.New("-agentcon, -public-keys, and at least one -key are required")
	}
	bin, err := filepath.Abs(bin)
	if err != nil {
		return fmt.Errorf("binary: %w", err)
	}
	pubs, err := os.ReadFile(pubsPath) //nolint:gosec // operator-supplied path
	if err != nil {
		return fmt.Errorf("public keys: %w", err)
	}
	dir, err := os.MkdirTemp("", "acbw")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	s := &smoke{bin: bin, dir: dir, state: filepath.Join(dir, "state"), auditPath: filepath.Join(dir, "audit.log"),
		repo: filepath.Join(dir, "repo"), gnupg: filepath.Join(dir, "g")}
	defer func() {
		_ = exec.Command("gpgconf", "--homedir", s.gnupg, "--kill", "all").Run() //nolint:gosec // smoke temp dir
		_ = os.RemoveAll(dir)
	}()
	ctx := context.Background()

	fmt.Println("1. start the bouncer with internal credentials sourced from Bitwarden")
	err = s.writeBitwardenPolicy(email, keys)
	if err != nil {
		return err
	}
	err = s.start()
	if err != nil {
		return err
	}
	defer s.stop()

	fmt.Println("2. the sidecar unlocks the vault; answer its prompts here")
	err = host.WaitReady(ctx, s.client, host.PromptOptions{Stdin: os.Stdin, Stderr: os.Stderr, Timeout: 5 * time.Minute})
	if err != nil {
		return fmt.Errorf("vault: %w", err)
	}

	fmt.Println("3. create a session with a repository claim")
	sess, err := s.client.CreateSession(ctx, "", "", "sign-bw-smoke", "", mgmt.WithClaims(map[string][]string{"repository": {claimed}}))
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	layout, err := s.agent(ctx, sess)
	if err != nil {
		return err
	}
	err = s.setupBitwardenRepo(string(pubs), layout.GitSign)
	if err != nil {
		return err
	}

	for i, k := range keys {
		fmt.Printf("%d. %s: git commit -S and git tag -s sign with %s, and verify\n", 4+i, k.item, k.fpr)
		err = s.signWith(ctx, k, i)
		if err != nil {
			return fmt.Errorf("%s: %w", k.item, err)
		}
	}

	fmt.Printf("%d. a key the signer does not hold fails the commit (expected failure)\n", 4+len(keys))
	_, err = s.git("config", "user.signingkey", "1111111111111111")
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	err = s.stage("unknown.txt")
	if err != nil {
		return err
	}
	out, err := s.gitWithPrompts(ctx, nil, "commit", "-q", "-S", "-m", "bw smoke: unknown key")
	if err == nil || !strings.Contains(out, "unknown signing key") {
		return fmt.Errorf("unknown key commit: %v: %s", err, out)
	}
	fmt.Println("   expected: " + firstLine(out, "bouncer:"))
	return nil
}

// signWith signs a commit and a tag with k and checks that git reports k's
// fingerprint as the signer.
func (s *smoke) signWith(ctx context.Context, k itemKey, n int) error {
	_, err := s.git("config", "user.signingkey", k.fpr)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	err = s.stage(fmt.Sprintf("file-%d.txt", n))
	if err != nil {
		return err
	}
	_, err = s.gitWithPrompts(ctx, nil, "commit", "-q", "-S", "-m", "bw smoke: "+k.item)
	if err != nil {
		return err
	}
	out, err := s.git("verify-commit", "HEAD")
	if err != nil || !strings.Contains(out, "Good signature") {
		return fmt.Errorf("verify-commit: %v: %s", err, out)
	}
	fmt.Println("   " + firstLine(out, "Good signature"))
	signer, err := s.git("log", "-1", "--format=%GF")
	if err != nil {
		return fmt.Errorf("log: %w", err)
	}
	if strings.TrimSpace(signer) != k.fpr {
		return fmt.Errorf("commit signed by %q, want %s", strings.TrimSpace(signer), k.fpr)
	}
	fmt.Println("   commit signed by " + k.fpr)
	tag := fmt.Sprintf("bw-smoke-%d", n)
	_, err = s.gitWithPrompts(ctx, nil, "tag", "-s", tag, "-m", "bw smoke tag")
	if err != nil {
		return err
	}
	out, err = s.git("verify-tag", tag)
	if err != nil || !strings.Contains(out, "Good signature") {
		return fmt.Errorf("verify-tag: %v: %s", err, out)
	}
	fmt.Println("   tag: " + firstLine(out, "Good signature"))
	return nil
}

func (s *smoke) writeBitwardenPolicy(email string, keys keyFlags) error {
	err := s.copyFilter()
	if err != nil {
		return err
	}
	proxyPort, err := freePort()
	if err != nil {
		return err
	}
	sshPort, err := freePort()
	if err != nil {
		return err
	}
	s.proxyAddr = net.JoinHostPort(loopback, strconv.Itoa(proxyPort))
	s.sshAddr = net.JoinHostPort(loopback, strconv.Itoa(sshPort))
	var creds, entries strings.Builder
	for _, k := range keys {
		name := "sign-" + k.item
		fmt.Fprintf(&creds, `  %s:
    internal: true
    cache: 10m
    private_key: {source: bitwarden, account: agent, item: %s, path: $.notes}
    password: {source: bitwarden, account: agent, item: %s, path: "$.fields[?(@.name=='password')].value"}
`, name, k.item, k.item)
		fmt.Fprintf(&entries, "              - {id: %s, credential: %s}\n", k.fpr, name)
	}
	policy := fmt.Sprintf(`
listen: %s
ssh_listen: %s
default_profile: agent
prompts: {notify: false, terminal: false, cli: true, timeout: 5m}
bitwarden:
  agent:
    email: %s
credentials:
%sprofiles:
  agent:
    unmatched: deny
    http:
      - name: commit-signing
        hosts: [signer.bouncer.internal]
        signer:
          openpgp:
            keys:
%s        filters: [ts/signing-repository-scope.ts]
`, s.proxyAddr, s.sshAddr, email, creds.String(), entries.String())
	s.policy = filepath.Join(s.dir, "policy.yaml")
	err = os.WriteFile(s.policy, []byte(policy), 0o600)
	if err != nil {
		return fmt.Errorf("write policy: %w", err)
	}
	return nil
}

func (s *smoke) setupBitwardenRepo(armoredPubs, wrapper string) error {
	err := os.Mkdir(s.gnupg, 0o700)
	if err != nil {
		return fmt.Errorf("gnupg: %w", err)
	}
	err = os.WriteFile(filepath.Join(s.gnupg, "gpg.conf"), []byte("trust-model always\n"), 0o600)
	if err != nil {
		return fmt.Errorf("gpg.conf: %w", err)
	}
	err = os.Mkdir(s.repo, 0o700)
	if err != nil {
		return fmt.Errorf("repo: %w", err)
	}
	steps := []struct {
		stdin string
		args  []string
	}{
		{armoredPubs, []string{"gpg", "--batch", "--import"}},
		{"", []string{"git", "init", "-q", "-b", "main"}},
		{"", []string{"git", "config", "user.name", "Bitwarden Smoke"}},
		{"", []string{"git", "config", "user.email", "agent@example.com"}},
		{"", []string{"git", "config", "gpg.format", "openpgp"}},
		{"", []string{"git", "config", "gpg.openpgp.program", wrapper}},
		{"", []string{"git", "remote", "add", "origin", "git@github.com:pastdev/agentcon.git"}},
	}
	for _, st := range steps {
		out, err := s.exec(st.stdin, st.args...)
		if err != nil {
			return fmt.Errorf("%s: %w: %s", strings.Join(st.args, " "), err, out)
		}
	}
	return nil
}

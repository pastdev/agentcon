package gitsign

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
)

// Help describes exactly what the helper does.
const Help = `agentcon bouncer git-sign: sign git objects through a bouncer signer.

Git runs this as gpg.openpgp.program, through /opt/agentcon/bin/git-sign:

  [gpg]
          format = openpgp
  [gpg "openpgp"]
          program = /opt/agentcon/bin/git-sign

Signing (git commit -S, git tag -s) runs:

  git-sign --status-fd=2 -bsau <user.signingkey>

  1. Reads the object git wants signed from stdin.
  2. Reads the signer URL from BOUNCER_SIGNER_URL.
  3. Takes the repository from git config agentcon.signing.repository, or
     else from "git remote get-url origin", normalized to host/path.
     With neither, it sends no repository and policy decides.
  4. POSTs the object, unchanged, to
     <BOUNCER_SIGNER_URL>?key=<key>&repository=<repository>
     through the proxy in HTTPS_PROXY, trusting SSL_CERT_FILE.
  5. On 200, writes the armored signature to stdout, the gpg status lines
     BEGIN_SIGNING and SIG_CREATED to the status fd, and one line to stderr
     naming the object type, repository, key, and signer host.
  6. On any other answer, writes bouncer's reason to stderr and exits 1.
     Git then aborts and leaves the index as it was.

Verification (git verify-commit, git log --show-signature) runs gpg on
PATH with the same arguments. Without gpg it exits 1.

  --dry-run   read stdin, print the request that would be sent to stderr,
              and send nothing.
`

// IO is the environment Main runs in.
type IO struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
	// Status returns the writer for a status fd.
	Status func(fd int) (io.Writer, error)
	Git    GitRunner
	Client *http.Client
	// Verify runs gpg for verification and returns its exit code.
	Verify func(ctx context.Context, args []string) (int, error)
}

// Main runs the helper and returns its exit code.
func Main(ctx context.Context, args []string, env IO) int {
	a, err := ParseArgs(args)
	if err != nil {
		_, _ = fmt.Fprintf(env.Stderr, "bouncer: %v (see agentcon bouncer git-sign --help)\n", err)
		return 2
	}
	switch a.Mode {
	case ModeHelp:
		_, _ = io.WriteString(env.Stdout, Help)
		return 0
	case ModeVerify:
		code, err := env.Verify(ctx, a.Raw)
		if err != nil {
			_, _ = fmt.Fprintf(env.Stderr, "bouncer: %v\n", err)
			return 1
		}
		return code
	case ModeSign:
	}
	return sign(ctx, a, env)
}

func sign(ctx context.Context, a Args, env IO) int {
	fail := func(format string, v ...any) int {
		_, _ = fmt.Fprintf(env.Stderr, "bouncer: "+format+"\n", v...)
		return 1
	}
	signerURL := env.Getenv(EnvSignerURL)
	if signerURL == "" {
		return fail("%s is not set (no signer service in this session's profile)", EnvSignerURL)
	}
	payload, err := io.ReadAll(io.LimitReader(env.Stdin, maxObject))
	if err != nil {
		return fail("read object: %v", err)
	}
	req := Request{URL: signerURL, Key: a.Key, Repository: Repository(ctx, env.Git), Payload: payload}
	if a.DryRun {
		d, err := req.Describe()
		if err != nil {
			return fail("%v", err)
		}
		_, _ = io.WriteString(env.Stderr, d)
		return 0
	}
	res, err := Sign(ctx, env.Client, req)
	var refused *RefusedError
	switch {
	case errors.As(err, &refused):
		return fail("%s", refused.Error())
	case err != nil:
		return fail("%v", err)
	}
	_, err = env.Stdout.Write(res.Armored)
	if err != nil {
		return fail("write signature: %v", err)
	}
	if a.StatusFD >= 0 {
		w, err := env.Status(a.StatusFD)
		if err != nil {
			return fail("status fd %d: %v", a.StatusFD, err)
		}
		_, err = io.WriteString(w, res.StatusLines())
		if err != nil {
			return fail("write status: %v", err)
		}
	}
	host := signerURL
	if u, err := url.Parse(signerURL); err == nil {
		host = u.Host
	}
	repo := req.Repository
	if repo == "" {
		repo = "(no repository)"
	}
	_, _ = fmt.Fprintf(env.Stderr, "bouncer: signed %s for %s with %s via %s\n", res.Type, repo, a.Key, host)
	return 0
}

// OSIO is the IO of a real process.
func OSIO() IO {
	return IO{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Getenv: os.Getenv,
		Status: func(fd int) (io.Writer, error) {
			switch fd {
			case 1:
				return os.Stdout, nil
			case 2:
				return os.Stderr, nil
			}
			f := os.NewFile(uintptr(fd), "status-fd")
			if f == nil {
				return nil, errors.New("not an open file")
			}
			return f, nil
		},
		Git:    RunGit,
		Verify: verifyWithGPG,
	}
}

func verifyWithGPG(ctx context.Context, args []string) (int, error) {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		return 1, errors.New("git-sign does not verify signatures and no gpg is installed")
	}
	cmd := exec.CommandContext(ctx, gpg, args...) //nolint:gosec // git's own verify arguments, passed to the gpg on PATH
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err = cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	if err != nil {
		return 1, fmt.Errorf("run gpg: %w", err)
	}
	return 0, nil
}

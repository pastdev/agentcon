package gitsign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// EnvSignerURL names the environment variable holding the signer URL.
const EnvSignerURL = "BOUNCER_SIGNER_URL"

// ConfigRepository is the git config key that overrides the repository
// derived from the origin remote.
const ConfigRepository = "agentcon.signing.repository"

// Response headers set by the signer. They match internal/bouncer/signer.
const (
	headerFingerprint = "X-Bouncer-Signer-Fingerprint"
	headerKeyAlgo     = "X-Bouncer-Signer-Key-Algorithm"
	headerHash        = "X-Bouncer-Signer-Hash"
	headerCreated     = "X-Bouncer-Signer-Created"
	headerType        = "X-Bouncer-Signer-Type"
)

// maxResponse bounds a signer response.
const maxResponse = 1 << 20

// maxObject is one byte over the largest object the signer accepts, so an
// oversize object still reaches the signer and is refused there.
const maxObject = 1<<20 + 1

// Mode is what git asked the program to do.
type Mode int

const (
	ModeSign Mode = iota + 1
	ModeVerify
	ModeHelp
)

// Args is a parsed gpg-style command line.
type Args struct {
	Mode Mode
	// StatusFD is the file descriptor for [GNUPG:] status lines, or -1.
	StatusFD int
	// Key is the -u/--local-user value.
	Key string
	// DryRun prints the request instead of sending it.
	DryRun bool
	// Raw is the full argument list, passed to gpg for verification.
	Raw []string
}

// ErrUsage marks a command line git would never send.
var ErrUsage = errors.New("usage")

// ParseArgs parses the arguments git passes to gpg.program. Signing is
// "--status-fd=2 -bsau <key>". Verification is "--keyid-format=long
// --status-fd=1 --verify <sig> -".
func ParseArgs(args []string) (Args, error) {
	a := Args{StatusFD: -1, Raw: args}
	var detach, sign bool
	for i := 0; i < len(args); i++ {
		arg := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%w: %s needs a value", ErrUsage, arg)
			}
			i++
			return args[i], nil
		}
		switch {
		case arg == "--help" || arg == "-h":
			return Args{Mode: ModeHelp}, nil
		case arg == "--verify":
			a.Mode = ModeVerify
			return a, nil
		case arg == "--dry-run":
			a.DryRun = true
		case strings.HasPrefix(arg, "--status-fd="):
			fd, err := strconv.Atoi(strings.TrimPrefix(arg, "--status-fd="))
			if err != nil || fd < 0 {
				return Args{}, fmt.Errorf("%w: bad %s", ErrUsage, arg)
			}
			a.StatusFD = fd
		case arg == "--status-fd":
			v, err := next()
			if err != nil {
				return Args{}, err
			}
			fd, err := strconv.Atoi(v)
			if err != nil || fd < 0 {
				return Args{}, fmt.Errorf("%w: bad --status-fd %s", ErrUsage, v)
			}
			a.StatusFD = fd
		case arg == "--local-user":
			v, err := next()
			if err != nil {
				return Args{}, err
			}
			a.Key = v
		case arg == "--detach-sign":
			detach, sign = true, true
		case arg == "--sign":
			sign = true
		case arg == "--armor":
		case strings.HasPrefix(arg, "--keyid-format"):
		case len(arg) > 1 && arg[0] == '-' && arg[1] != '-':
			for j, c := range arg[1:] {
				switch c {
				case 'b':
					detach, sign = true, true
				case 's':
					sign = true
				case 'a':
				case 'u':
					if j != len(arg)-2 {
						return Args{}, fmt.Errorf("%w: -u must end %s", ErrUsage, arg)
					}
					v, err := next()
					if err != nil {
						return Args{}, err
					}
					a.Key = v
				default:
					return Args{}, fmt.Errorf("%w: unsupported option -%c", ErrUsage, c)
				}
			}
		default:
			return Args{}, fmt.Errorf("%w: unsupported argument %q", ErrUsage, arg)
		}
	}
	if !sign || !detach {
		return Args{}, fmt.Errorf("%w: only detached signing (-bsau <key>) and --verify are supported", ErrUsage)
	}
	if a.Key == "" {
		return Args{}, fmt.Errorf("%w: a signing key (-u <key>) is required; set user.signingkey", ErrUsage)
	}
	a.Mode = ModeSign
	return a, nil
}

// Result is a signature from the signer.
type Result struct {
	Armored     []byte
	Fingerprint string
	KeyAlgo     int
	Hash        int
	Created     int64
	Type        string
}

// StatusLines are the gpg status lines git reads after signing. Git only
// requires SIG_CREATED, and the format follows gpg's.
func (r *Result) StatusLines() string {
	return fmt.Sprintf("[GNUPG:] BEGIN_SIGNING H%d\n[GNUPG:] SIG_CREATED D %d %d 00 %d %s\n",
		r.Hash, r.KeyAlgo, r.Hash, r.Created, r.Fingerprint)
}

// RefusedError is a non-200 answer from the signer or bouncer.
type RefusedError struct {
	Status int
	Body   string
}

func (e *RefusedError) Error() string {
	msg := strings.TrimSpace(e.Body)
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	return fmt.Sprintf("signer answered %d: %s", e.Status, msg)
}

// Request is one signing request.
type Request struct {
	// URL is the signer URL, normally from BOUNCER_SIGNER_URL.
	URL        string
	Key        string
	Repository string
	Payload    []byte
}

// Target is the URL the request is sent to.
func (r Request) Target() (string, error) {
	u, err := url.Parse(r.URL)
	if err != nil {
		return "", fmt.Errorf("signer url: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("signer url %q: want https://host/path", r.URL)
	}
	q := u.Query()
	q.Set("key", r.Key)
	if r.Repository != "" {
		q.Set("repository", r.Repository)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Describe is what --dry-run prints.
func (r Request) Describe() (string, error) {
	target, err := r.Target()
	if err != nil {
		return "", err
	}
	repo := r.Repository
	if repo == "" {
		repo = "(none)"
	}
	return fmt.Sprintf("POST %s\nrepository: %s\nkey: %s\nsha256: %x\nbytes: %d\n",
		target, repo, r.Key, sha256.Sum256(r.Payload), len(r.Payload)), nil
}

// Sign sends the request. A nil client uses one that honors the proxy
// environment and SSL_CERT_FILE.
func Sign(ctx context.Context, client *http.Client, r Request) (*Result, error) {
	target, err := r.Target()
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(r.Payload))
	if err != nil {
		return nil, fmt.Errorf("signer request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-git-object")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("signer request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return nil, fmt.Errorf("signer response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &RefusedError{Status: resp.StatusCode, Body: string(body)}
	}
	if !bytes.HasPrefix(body, []byte("-----BEGIN PGP SIGNATURE-----")) {
		return nil, errors.New("signer response: not an armored signature")
	}
	res := &Result{Armored: body, Fingerprint: resp.Header.Get(headerFingerprint), Type: resp.Header.Get(headerType)}
	res.KeyAlgo, err = strconv.Atoi(resp.Header.Get(headerKeyAlgo))
	if err != nil {
		return nil, fmt.Errorf("signer response: bad %s", headerKeyAlgo)
	}
	res.Hash, err = strconv.Atoi(resp.Header.Get(headerHash))
	if err != nil {
		return nil, fmt.Errorf("signer response: bad %s", headerHash)
	}
	res.Created, err = strconv.ParseInt(resp.Header.Get(headerCreated), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("signer response: bad %s", headerCreated)
	}
	if res.Fingerprint == "" {
		return nil, fmt.Errorf("signer response: missing %s", headerFingerprint)
	}
	return res, nil
}

// GitRunner runs git with args and returns its stdout.
type GitRunner func(ctx context.Context, args ...string) (string, error)

// RunGit runs the git on PATH in the current directory.
func RunGit(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "git", args...).Output() //nolint:gosec // fixed git subcommands from this package
	if err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

// Repository is git config agentcon.signing.repository, else the
// normalized origin remote, else "" when neither is available.
func Repository(ctx context.Context, git GitRunner) string {
	v, err := git(ctx, "config", "--get", ConfigRepository)
	if err == nil && v != "" {
		return v
	}
	remote, err := git(ctx, "remote", "get-url", "origin")
	if err != nil || remote == "" {
		return ""
	}
	repo, err := NormalizeRemote(remote)
	if err != nil {
		return ""
	}
	return repo
}

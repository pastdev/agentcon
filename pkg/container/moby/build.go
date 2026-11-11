package moby

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	controlapi "github.com/moby/buildkit/api/services/control"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/filesync"
	"github.com/moby/moby/api/types/build"
	"github.com/moby/moby/api/types/jsonstream"
	"github.com/moby/moby/client"
	"github.com/moby/patternmatcher/ignorefile"
	"github.com/pastdev/agentcon/pkg/container"
	"github.com/tonistiigi/fsutil"
	"google.golang.org/protobuf/proto"
)

const (
	defaultDockerfile = "Dockerfile"
	buildkitTraceID   = "moby.buildkit.trace"
	// remoteContextSession tells the daemon to read the context from the
	// build session.
	remoteContextSession = "client-session"
)

func (r *Runtime) Build(ctx context.Context, spec container.Build) error {
	if spec.Context == "" {
		return fmt.Errorf("build context is required")
	}
	out := spec.Output
	if out == nil {
		out = os.Stderr
	}

	_, err := fmt.Fprintf(out, "building %s\n", buildTagSummary(spec.Tags))
	if err != nil {
		return fmt.Errorf("write build header: %w", err)
	}

	in, err := buildInputs(spec.Context, spec.Dockerfile)
	if err != nil {
		return err
	}
	dirs, err := in.sources()
	if err != nil {
		return err
	}

	// Send the context through a BuildKit session, as docker build does.
	// Uploading it as the request body can stall in "load remote build
	// context" on Docker Desktop.
	sess, err := session.NewSession(ctx, sharedKey(in.contextDir))
	if err != nil {
		return fmt.Errorf("build session: %w", err)
	}
	sess.Allow(filesync.NewFSSyncProvider(dirs))

	buildCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	ran := make(chan struct{})
	go func() {
		defer close(ran)
		err := sess.Run(buildCtx, func(ctx context.Context, proto string, meta map[string][]string) (net.Conn, error) {
			return r.api.DialHijack(ctx, "/session", proto, meta)
		})
		if err != nil {
			cancel(fmt.Errorf("build session: %w", err))
		}
	}()

	err = r.imageBuild(buildCtx, spec, sess.ID(), in.dockerfileName, out)
	_ = sess.Close()
	<-ran
	cause := context.Cause(buildCtx)
	if err != nil && cause != nil && !errors.Is(cause, context.Canceled) {
		return cause //nolint:wrapcheck // the session goroutine already wrapped it
	}
	return err
}

func (r *Runtime) imageBuild(ctx context.Context, spec container.Build, sessionID, dockerfile string, out io.Writer) error {
	result, err := r.api.ImageBuild(ctx, nil, client.ImageBuildOptions{
		Tags:          spec.Tags,
		Dockerfile:    dockerfile,
		Remove:        true,
		PullParent:    spec.PullParent,
		Version:       build.BuilderBuildKit,
		SessionID:     sessionID,
		RemoteContext: remoteContextSession,
	})
	if err != nil {
		return fmt.Errorf("build image: %w", err)
	}
	defer func() { _ = result.Body.Close() }()

	err = displayBuild(ctx, result.Body, out)
	if err != nil {
		return err
	}
	return nil
}

// buildInput is what a session build serves: the context, the directory
// holding the Dockerfile, and the context paths to leave out.
type buildInput struct {
	contextDir     string
	dockerfileDir  string
	dockerfileName string
	excludes       []string
}

// buildInputs resolves a context and a Dockerfile path relative to it.
// Ignore patterns come from <Dockerfile>.dockerignore beside the Dockerfile
// when it exists, else from .dockerignore at the context root.
func buildInputs(contextDir, dockerfile string) (buildInput, error) {
	if dockerfile == "" {
		dockerfile = defaultDockerfile
	}
	path := filepath.Join(contextDir, dockerfile)
	in := buildInput{
		contextDir:     contextDir,
		dockerfileDir:  filepath.Dir(path),
		dockerfileName: filepath.Base(path),
	}
	for _, ignore := range []string{path + ".dockerignore", filepath.Join(contextDir, ".dockerignore")} {
		f, err := os.Open(ignore) //nolint:gosec // beside the build context from config
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return buildInput{}, fmt.Errorf("ignore file: %w", err)
		}
		in.excludes, err = ignorefile.ReadAll(f)
		closeErr := f.Close()
		if err != nil {
			return buildInput{}, fmt.Errorf("ignore file %s: %w", ignore, err)
		}
		if closeErr != nil {
			return buildInput{}, fmt.Errorf("ignore file %s: %w", ignore, closeErr)
		}
		break
	}
	return in, nil
}

// sources serves the context, without excluded paths, and the Dockerfile
// directory under the names BuildKit's Dockerfile frontend asks for.
func (in buildInput) sources() (filesync.StaticDirSource, error) {
	contextFS, err := fsutil.NewFS(in.contextDir)
	if err != nil {
		return nil, fmt.Errorf("build context: %w", err)
	}
	contextFS, err = fsutil.NewFilterFS(contextFS, &fsutil.FilterOpt{ExcludePatterns: in.excludes})
	if err != nil {
		return nil, fmt.Errorf("build context: %w", err)
	}
	dockerfileFS, err := fsutil.NewFS(in.dockerfileDir)
	if err != nil {
		return nil, fmt.Errorf("dockerfile directory: %w", err)
	}
	return filesync.StaticDirSource{
		"context":    contextFS,
		"dockerfile": dockerfileFS,
	}, nil
}

// sharedKey lets BuildKit reuse what it already received for this context.
func sharedKey(contextDir string) string {
	abs, err := filepath.Abs(contextDir)
	if err != nil {
		abs = contextDir
	}
	sum := sha256.Sum256([]byte(abs))
	return hex.EncodeToString(sum[:])
}

func buildTagSummary(tags []string) string {
	if len(tags) == 0 {
		return "image"
	}
	return strings.Join(tags, ", ")
}

func displayBuild(ctx context.Context, in io.Reader, out io.Writer) error {
	progress := newPlainProgress(out)
	dec := json.NewDecoder(in)
	for {
		err := ctx.Err()
		if err != nil {
			return fmt.Errorf("build image: %w", err)
		}
		var msg jsonstream.Message
		err = dec.Decode(&msg)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("decode build output: %w", err)
		}
		if msg.Error != nil {
			return fmt.Errorf("build: %w", msg.Error)
		}
		if msg.Aux != nil {
			resp, ok := statusResponseFromMessage(msg)
			if !ok {
				continue
			}
			err = progress.apply(resp)
			if err != nil {
				return err
			}
			continue
		}
		if msg.Stream != "" {
			_, err = io.WriteString(out, msg.Stream)
			if err != nil {
				return fmt.Errorf("write build output: %w", err)
			}
			continue
		}
		if msg.Status != "" {
			_, err = fmt.Fprintln(out, msg.Status)
			if err != nil {
				return fmt.Errorf("write build status: %w", err)
			}
		}
	}
}

func statusResponseFromMessage(msg jsonstream.Message) (*controlapi.StatusResponse, bool) {
	if msg.ID != buildkitTraceID || msg.Aux == nil {
		return nil, false
	}
	var raw []byte
	err := json.Unmarshal(*msg.Aux, &raw)
	if err != nil {
		return nil, false
	}
	resp := &controlapi.StatusResponse{}
	err = proto.Unmarshal(raw, resp)
	if err != nil {
		return nil, false
	}
	return resp, true
}

type plainProgress struct {
	out       io.Writer
	index     map[string]int
	started   map[string]time.Time
	named     map[string]bool
	completed map[string]bool
	next      int
}

func newPlainProgress(out io.Writer) *plainProgress {
	return &plainProgress{
		out:       out,
		index:     map[string]int{},
		started:   map[string]time.Time{},
		named:     map[string]bool{},
		completed: map[string]bool{},
	}
}

func (p *plainProgress) apply(resp *controlapi.StatusResponse) error {
	for _, v := range resp.Vertexes {
		err := p.vertex(v)
		if err != nil {
			return err
		}
	}
	for _, s := range resp.Statuses {
		err := p.status(s)
		if err != nil {
			return err
		}
	}
	for _, l := range resp.Logs {
		err := p.log(l)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *plainProgress) vertex(v *controlapi.Vertex) error {
	if v == nil || v.Digest == "" {
		return nil
	}
	idx := p.id(v.Digest)
	if v.Started != nil && !p.named[v.Digest] {
		if len(p.named) > 0 {
			err := p.printf("\n")
			if err != nil {
				return err
			}
		}
		p.named[v.Digest] = true
		p.started[v.Digest] = v.Started.AsTime()
		err := p.printf("#%d %s\n", idx, v.Name)
		if err != nil {
			return err
		}
	}
	if v.Completed == nil || p.completed[v.Digest] {
		return nil
	}
	p.completed[v.Digest] = true
	switch {
	case v.Error != "":
		return p.printf("#%d ERROR: %s\n", idx, v.Error)
	case v.Cached:
		return p.printf("#%d CACHED\n", idx)
	default:
		suffix := ""
		start, ok := p.started[v.Digest]
		if ok {
			suffix = fmt.Sprintf(" %.1fs", v.Completed.AsTime().Sub(start).Seconds())
		}
		return p.printf("#%d DONE%s\n", idx, suffix)
	}
}

func (p *plainProgress) printf(format string, args ...any) error {
	_, err := fmt.Fprintf(p.out, format, args...)
	if err != nil {
		return fmt.Errorf("write build progress: %w", err)
	}
	return nil
}

func (p *plainProgress) status(s *controlapi.VertexStatus) error {
	if s == nil {
		return nil
	}
	idx := p.id(s.Vertex)
	name := s.Name
	if name == "" {
		name = s.ID
	}
	detail := ""
	if s.Total != 0 {
		detail = fmt.Sprintf(" %d / %d", s.Current, s.Total)
	} else if s.Current != 0 {
		detail = fmt.Sprintf(" %d", s.Current)
	}
	done := ""
	if s.Completed != nil {
		done = " done"
	}
	return p.printf("#%d %s%s%s\n", idx, name, detail, done)
}

func (p *plainProgress) log(l *controlapi.VertexLog) error {
	if l == nil || len(l.Msg) == 0 {
		return nil
	}
	idx := p.id(l.Vertex)
	text := string(l.Msg)
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	for _, line := range strings.SplitAfter(text, "\n") {
		if line == "" || line == "\n" {
			continue
		}
		if !strings.HasPrefix(line, "#") {
			err := p.printf("#%d %s", idx, line)
			if err != nil {
				return err
			}
			continue
		}
		err := p.printf("%s", line)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *plainProgress) id(digest string) int {
	if digest == "" {
		return 0
	}
	n, ok := p.index[digest]
	if ok {
		return n
	}
	p.next++
	p.index[digest] = p.next
	return p.next
}

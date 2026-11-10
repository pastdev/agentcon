package moby

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	controlapi "github.com/moby/buildkit/api/services/control"
	"github.com/moby/moby/api/types/build"
	"github.com/moby/moby/api/types/jsonstream"
	"github.com/moby/moby/client"
	"github.com/pastdev/agentcon/pkg/container"
	"google.golang.org/protobuf/proto"
)

const (
	defaultDockerfile = "Dockerfile"
	buildkitTraceID   = "moby.buildkit.trace"
)

func (r *Runtime) Build(ctx context.Context, spec container.Build) error {
	if spec.Context == "" && spec.Files == nil {
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

	dockerfile := spec.Dockerfile
	if dockerfile == "" {
		dockerfile = defaultDockerfile
	}

	var archive io.Reader
	if spec.Files != nil {
		archive, err = tarFiles(spec.Files)
	} else {
		archive, err = tarDirectory(spec.Context)
	}
	if err != nil {
		return fmt.Errorf("pack build context: %w", err)
	}

	result, err := r.api.ImageBuild(ctx, archive, client.ImageBuildOptions{
		Tags:       spec.Tags,
		Dockerfile: filepath.ToSlash(dockerfile),
		Remove:     true,
		PullParent: spec.PullParent,
		Version:    build.BuilderBuildKit,
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

func buildTagSummary(tags []string) string {
	if len(tags) == 0 {
		return "image"
	}
	return strings.Join(tags, ", ")
}

// tarFiles packs an in-memory build context. Names are sorted and headers
// fixed, so the same files always produce the same archive.
func tarFiles(files map[string][]byte) (io.Reader, error) {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	buf := &bytes.Buffer{}
	tw := tar.NewWriter(buf)
	for _, name := range names {
		data := files[name]
		err := tw.WriteHeader(&tar.Header{
			Name:     filepath.ToSlash(name),
			Mode:     0o644,
			Size:     int64(len(data)),
			Typeflag: tar.TypeReg,
		})
		if err != nil {
			return nil, fmt.Errorf("tar header %s: %w", name, err)
		}
		_, err = tw.Write(data)
		if err != nil {
			return nil, fmt.Errorf("tar %s: %w", name, err)
		}
	}
	err := tw.Close()
	if err != nil {
		return nil, fmt.Errorf("close tar: %w", err)
	}
	return buf, nil
}

func tarDirectory(root string) (io.Reader, error) {
	buf := &bytes.Buffer{}
	tw := tar.NewWriter(buf)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("relative path %s: %w", path, err)
		}
		name := filepath.ToSlash(rel)
		if name == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("tar header %s: %w", name, err)
		}
		header.Name = name
		if d.Type()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return fmt.Errorf("readlink %s: %w", path, err)
			}
			header.Typeflag = tar.TypeSymlink
			header.Linkname = target
		}
		err = tw.WriteHeader(header)
		if err != nil {
			return fmt.Errorf("write tar header %s: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		//nolint:gosec // build context path is supplied by config
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		_, err = io.Copy(tw, file)
		closeErr := file.Close()
		if err != nil {
			return fmt.Errorf("copy %s: %w", path, err)
		}
		if closeErr != nil {
			return fmt.Errorf("close %s: %w", path, closeErr)
		}
		return nil
	})
	if err != nil {
		_ = tw.Close()
		return nil, fmt.Errorf("walk build context: %w", err)
	}
	err = tw.Close()
	if err != nil {
		return nil, fmt.Errorf("close tar: %w", err)
	}
	return buf, nil
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

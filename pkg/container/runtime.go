package container

import (
	"context"
	"fmt"
	"io"
)

type Runtime interface {
	Run(ctx context.Context, spec Spec) error
	Build(ctx context.Context, spec Build) error
	// ImageExists reports whether an image is present locally.
	ImageExists(ctx context.Context, ref string) (bool, error)
	// Pull fetches an image from its registry, writing progress to out.
	Pull(ctx context.Context, ref string, out io.Writer) error
	Create(ctx context.Context, spec Spec) (string, error)
	Start(ctx context.Context, id string) error
	AttachStartWait(ctx context.Context, id string, spec Spec) error
	CopyTo(ctx context.Context, id, dest string, tar io.Reader) error
	Exec(ctx context.Context, id string, spec Exec) error
	Inspect(ctx context.Context, id string) (Info, error)
	Remove(ctx context.Context, id string, force bool) error
	CreateNetwork(ctx context.Context, spec NetworkSpec) (string, error)
	InspectNetwork(ctx context.Context, id string) (NetworkInfo, error)
	ConnectNetwork(ctx context.Context, networkID, containerID string) error
	RemoveNetwork(ctx context.Context, id string) error
}

type ExitError struct {
	Code int
}

type Mount struct {
	Source string
	Target string
}

type Port struct {
	HostIP        string
	HostPort      string
	ContainerPort string
	Protocol      string
}

type NetworkSpec struct {
	Name     string
	Internal bool
	Labels   map[string]string
}

type NetworkInfo struct {
	ID     string
	Name   string
	Subnet string
}

type Endpoint struct {
	IP string
}

type Info struct {
	ID       string
	Networks map[string]Endpoint
}

type Exec struct {
	Cmd    []string
	Env    []string
	User   string
	Detach bool
}

type Spec struct {
	Name       string
	Image      string
	User       string
	GroupAdd   []string
	WorkDir    string
	Env        []string
	Mounts     []Mount
	Args       []string
	Entrypoint []string
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	TTY        bool
	AutoRemove bool
	Networks   []string
	Ports      []Port
	Labels     map[string]string
	ExtraHosts []string
}

type Build struct {
	Context    string
	Dockerfile string
	Tags       []string
	Output     io.Writer
	// PullParent fetches base images even when a copy is cached.
	PullParent bool
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("container exit status %d", e.Code)
}

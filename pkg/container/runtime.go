package container

import (
	"context"
	"fmt"
	"io"
)

type Runtime interface {
	Run(ctx context.Context, spec Spec) error
}

type ExitError struct {
	Code int
}

type Mount struct {
	Source string
	Target string
}

type Spec struct {
	Image    string
	User     string
	GroupAdd []string
	WorkDir  string
	Env      []string
	Mounts   []Mount
	Args     []string
	Stdin    io.Reader
	Stdout   io.Writer
	Stderr   io.Writer
	TTY      bool
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("container exit status %d", e.Code)
}

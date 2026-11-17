// Package crederr holds the errors a bouncer credential source returns.
package crederr

import "errors"

// MaxStderr caps CommandError.Stderr, in bytes.
const MaxStderr = 4 << 10

// CommandError is a failed `source: command` credential. Its Error text
// names only the executable and how it failed, such as
// "op: exit status 1", never its arguments, stdout, or stderr.
type CommandError struct {
	// Name is the executable, without its arguments.
	Name string
	// Err is how it failed, such as an *exec.ExitError.
	Err error
	// Stderr is the command's standard error, trimmed and capped at
	// MaxStderr bytes. It may contain secrets. Show it only to the operator.
	Stderr string
}

func (e *CommandError) Error() string {
	return e.Name + ": " + e.Err.Error()
}

func (e *CommandError) Unwrap() error {
	return e.Err
}

// Stderr returns the stderr of the first CommandError in err's chain, or ""
// when there is none.
func Stderr(err error) string {
	var ce *CommandError
	if !errors.As(err, &ce) {
		return ""
	}
	return ce.Stderr
}

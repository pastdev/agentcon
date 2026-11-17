package crederr_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/pastdev/agentcon/pkg/bouncer/crederr"
	"github.com/stretchr/testify/assert"
)

func TestCommandError(t *testing.T) {
	type testCase struct {
		err        error
		wantText   string
		wantStderr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		assert.Equal(t, tc.wantText, tc.err.Error())
		assert.Equal(t, tc.wantStderr, crederr.Stderr(tc.err))
	}

	exit := errors.New("exit status 1")
	t.Run("keeps stderr out of the text", func(t *testing.T) {
		tester(t, testCase{
			err:        &crederr.CommandError{Name: "op", Err: exit, Stderr: "token s3cret rejected"},
			wantText:   "op: exit status 1",
			wantStderr: "token s3cret rejected",
		})
	})
	t.Run("finds stderr through wrapping", func(t *testing.T) {
		tester(t, testCase{
			err:        fmt.Errorf("credential x: %w", &crederr.CommandError{Name: "op", Err: exit, Stderr: "locked"}),
			wantText:   "credential x: op: exit status 1",
			wantStderr: "locked",
		})
	})
	t.Run("has no stderr for other errors", func(t *testing.T) {
		tester(t, testCase{err: exit, wantText: "exit status 1"})
	})
	t.Run("unwraps to the exec failure", func(t *testing.T) {
		assert.ErrorIs(t, &crederr.CommandError{Name: "op", Err: exit}, exit)
	})
}

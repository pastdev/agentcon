package app

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pastdev/agentcon/internal/bouncer/prompt"
)

type fakeAnswerer struct {
	answered *prompt.Answer
	declined bool
}

func (f *fakeAnswerer) AnswerPrompt(_ string, a prompt.Answer) error {
	f.answered = &a
	return nil
}

func (f *fakeAnswerer) DeclinePrompt(string) error {
	f.declined = true
	return nil
}

func TestAnswerAtTerminal(t *testing.T) {
	type testCase struct {
		kind         prompt.Kind
		input        string
		wantAnswer   *prompt.Answer
		wantDeclined bool
		wantErr      bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		r, w, err := os.Pipe()
		require.NoError(t, err)
		t.Cleanup(func() { _ = r.Close() })
		_, err = w.WriteString(tc.input)
		require.NoError(t, err)
		_ = w.Close()
		f := &fakeAnswerer{}
		err = AnswerAtTerminal(context.Background(), f, r, io.Discard, prompt.Pending{ID: "a1", Kind: tc.kind, Source: "test", Message: "?"})
		if tc.wantErr {
			require.Error(t, err)
			assert.Equal(t, &fakeAnswerer{}, f, "sent after an error")
			return
		}
		require.NoError(t, err)
		assert.Equal(t, &fakeAnswerer{answered: tc.wantAnswer, declined: tc.wantDeclined}, f)
	}

	t.Run("text", func(t *testing.T) {
		tester(t, testCase{kind: prompt.KindText, input: " 123456 \n", wantAnswer: &prompt.Answer{Value: "123456"}})
	})
	t.Run("empty text declines", func(t *testing.T) {
		tester(t, testCase{kind: prompt.KindText, input: "\n", wantDeclined: true})
	})
	t.Run("confirm for session", func(t *testing.T) {
		tester(t, testCase{kind: prompt.KindConfirm, input: "s\n", wantAnswer: &prompt.Answer{Allow: true, Remember: true}})
	})
	t.Run("confirm asks again after a bad answer", func(t *testing.T) {
		tester(t, testCase{kind: prompt.KindConfirm, input: "maybe\nn\n", wantAnswer: &prompt.Answer{}})
	})
	t.Run("confirm with closed input", func(t *testing.T) {
		tester(t, testCase{kind: prompt.KindConfirm, input: "", wantErr: true})
	})
	t.Run("ctrl-c declines", func(t *testing.T) {
		tester(t, testCase{kind: prompt.KindConfirm, input: "\x03", wantDeclined: true})
	})
	t.Run("secret needs a terminal", func(t *testing.T) {
		tester(t, testCase{kind: prompt.KindSecret, input: "hunter2\n", wantErr: true})
	})
}

package run

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReadSecretBytes(t *testing.T) {
	type testCase struct {
		ctx         context.Context
		input       []byte
		echo        *bytes.Buffer
		want        string
		wantErr     error
		errContains string
		wantEcho    string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		ctx := tc.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		var echo io.Writer
		if tc.echo != nil {
			echo = tc.echo
		}
		got, err := readSecretBytes(ctx, bytes.NewReader(tc.input), echo)
		if tc.wantErr != nil {
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v", err)
			}
			return
		}
		if tc.errContains != "" {
			if err == nil || !strings.Contains(err.Error(), tc.errContains) {
				t.Fatalf("got %v", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != tc.want {
			t.Fatalf("got %q", got)
		}
		if tc.echo != nil && tc.echo.String() != tc.wantEcho {
			t.Fatalf("echo %q", tc.echo.String())
		}
	}

	t.Run("treats ctrl-c as interrupt", func(t *testing.T) {
		tester(t, testCase{input: []byte{0x03}, wantErr: ErrInterrupted})
	})
	t.Run("submits on line feed", func(t *testing.T) {
		tester(t, testCase{input: []byte("secret\n"), want: "secret"})
	})
	t.Run("submits on carriage return", func(t *testing.T) {
		tester(t, testCase{input: []byte("secret\r"), want: "secret"})
	})
	t.Run("erases backspace from the value", func(t *testing.T) {
		tester(t, testCase{input: []byte("seX\x7fcret\n"), want: "secret"})
	})
	t.Run("returns canceled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		tester(t, testCase{
			ctx:         ctx,
			input:       []byte("secret\n"),
			errContains: "canceled",
		})
	})
	t.Run("returns eof on empty input", func(t *testing.T) {
		tester(t, testCase{wantErr: io.EOF})
	})
	t.Run("echoes printable bytes and backspace", func(t *testing.T) {
		var out bytes.Buffer
		tester(t, testCase{
			input:    []byte("12X\x7f3456\n"),
			echo:     &out,
			want:     "123456",
			wantEcho: "12X\b \b3456",
		})
	})
}

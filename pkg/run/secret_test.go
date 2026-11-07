package run

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReadSecretBytesCtrlC(t *testing.T) {
	_, err := readSecretBytes(context.Background(), bytes.NewReader([]byte{0x03}))
	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("got %v", err)
	}
}

func TestReadSecretBytesEnter(t *testing.T) {
	got, err := readSecretBytes(context.Background(), bytes.NewReader([]byte("secret\n")))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret" {
		t.Fatalf("got %q", got)
	}
}

func TestReadSecretBytesBackspace(t *testing.T) {
	got, err := readSecretBytes(context.Background(), bytes.NewReader([]byte("seX\x7fcret\n")))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret" {
		t.Fatalf("got %q", got)
	}
}

func TestReadSecretBytesCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := readSecretBytes(ctx, bytes.NewReader([]byte("secret\n")))
	if !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("got %v", err)
	}
}

func TestReadSecretBytesEOF(t *testing.T) {
	_, err := readSecretBytes(context.Background(), bytes.NewReader(nil))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("got %v", err)
	}
}

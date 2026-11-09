//go:build issue15

// Command prompter runs the daemon's terminal prompter on this process's
// terminal and raises a secret, a text, and a confirm prompt in turn. It
// prints what each asker received so a driver can check the answers.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pastdev/agentcon/internal/bouncer/daemon"
	"github.com/pastdev/agentcon/internal/bouncer/prompt"
	"github.com/pastdev/agentcon/pkg/term"
)

func main() {
	dir, err := os.MkdirTemp("", "issue15-smoke")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	cfg := filepath.Join(dir, "config.yaml")
	err = os.WriteFile(cfg, []byte("default_profile: p\nprofiles:\n  p: {}\nprompts: {notify: false}\n"), 0o600)
	if err != nil {
		panic(err)
	}
	d, err := daemon.New(daemon.Options{ConfigPath: cfg, StateDir: filepath.Join(dir, "state"), Logf: func(string, ...any) {}})
	if err != nil {
		panic(err)
	}
	if !term.IsTerminal(0) {
		panic("stdin is not a terminal")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.RunTerminalPrompter(ctx, term.New(0), os.Stdout)
	}()
	for _, k := range []prompt.Kind{prompt.KindSecret, prompt.KindText, prompt.KindConfirm, prompt.KindSecret} {
		a, err := d.Prompts.Ask(ctx, prompt.Question{Kind: k, Source: "smoke", Message: string(k) + "?"})
		fmt.Printf("\nRESULT kind=%s allow=%v remember=%v value_len=%d value_is_hunter=%v err=%v\n",
			k, a.Allow, a.Remember, len(a.Value), a.Value == "hunter 2", err)
	}
	cancel()
	<-done
	fmt.Println("DONE")
}

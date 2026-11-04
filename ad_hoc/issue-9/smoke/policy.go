package main

import (
	"fmt"
	"path/filepath"
	"runtime"

	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
)

const (
	filterPath   = "ts/filters/tag.ts"
	taggedBody   = "tagged:pong"
	filterDenied = "raw response blocked by filter"
)

func smokeDir() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("smoke dir: no caller")
	}
	return filepath.Dir(file), nil
}

func smokeTSFiles() (map[string]string, error) {
	dir, err := smokeDir()
	if err != nil {
		return nil, err
	}
	files, err := bouncercfg.CollectTSFiles([]string{dir})
	if err != nil {
		return nil, fmt.Errorf("collect ts files: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no ts files under %s", dir)
	}
	return files, nil
}

func smokePolicy(listen, sshListen, host, credYAML string) []byte {
	return []byte(fmt.Sprintf(`
listen: %s
ssh_listen: %s
default_profile: agent
approvals: {notify: false, terminal: false, cli: false}
credentials:
%s
profiles:
  agent:
    unmatched: deny
    services:
      - name: smoke
        hosts: [%q]
        credential: %s
        insecure: true
        inject: {bearer: true}
        filters:
          - %s
        rules:
          - action: allow
            methods: [GET]
            path: /secret
`, listen, sshListen, credYAML, host, credName, filterPath))
}

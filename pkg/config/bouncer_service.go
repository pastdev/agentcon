package config

import (
	"fmt"
	"os"

	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
)

// LoadBouncerService loads a folder-layer directory or a standalone policy file.
func LoadBouncerService(path string) (*bouncercfg.Config, error) {
	info, err := os.Stat(path)
	if err == nil && info.IsDir() {
		doc, err := bouncercfg.LoadDir(path)
		if err != nil {
			return nil, fmt.Errorf("load bouncer policy: %w", err)
		}
		return doc, nil
	}
	doc, err := bouncercfg.Load(path)
	if err != nil {
		return nil, fmt.Errorf("load bouncer policy: %w", err)
	}
	return doc, nil
}

// BouncerLoader returns a reload function for a policy file or directory.
func BouncerLoader(path string) func() (*bouncercfg.Config, error) {
	return func() (*bouncercfg.Config, error) {
		return LoadBouncerService(path)
	}
}

func (c *Config) bouncerService(name string) (*bouncercfg.Config, error) {
	spec, ok := c.Contexts[name]
	if !ok || spec.Bouncer == nil {
		return nil, nil
	}
	err := spec.Bouncer.Init()
	if err != nil {
		return nil, fmt.Errorf("init bouncer config: %w", err)
	}
	return spec.Bouncer, nil
}

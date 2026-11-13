// Package bouncertest runs a bouncer's *.test.yaml specs against its
// materialized policy, the way the sidecar would load it.
package bouncertest

import (
	"fmt"
	"path/filepath"

	"github.com/pastdev/agentcon/internal/bouncer/testrunner"
	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
)

// Suite is one bouncer's policy and the directory of its specs.
type Suite struct {
	Bouncer    string
	PolicyYAML []byte
	TSFiles    map[string]string
	TestsDir   string
}

// Report holds the results of every spec in a suite.
type Report struct {
	Bouncer string
	Specs   []SpecReport
}

// SpecReport is one spec file. Err is set when the spec could not be loaded
// or run, and Results is then empty.
type SpecReport struct {
	// Path is relative to the parent of the tests directory, such as
	// tests/bouncers.test.yaml.
	Path    string
	Results []testrunner.Result
	Err     error
}

// Failed counts failed cases plus specs that could not be loaded.
func (r Report) Failed() int {
	n := 0
	for _, s := range r.Specs {
		if s.Err != nil {
			n++
			continue
		}
		for _, res := range s.Results {
			if !res.Passed {
				n++
			}
		}
	}
	return n
}

// Run writes the suite's layout into dir and runs every spec under its
// tests directory. The caller owns dir. A spec that fails to load is
// recorded in its SpecReport and the rest still run.
func Run(suite Suite, dir string) (Report, error) {
	err := bouncercfg.WriteLayout(bouncercfg.DirFS(dir), suite.PolicyYAML, suite.TSFiles)
	if err != nil {
		return Report{}, fmt.Errorf("write bouncer layout: %w", err)
	}
	files, err := testrunner.Find([]string{suite.TestsDir})
	if err != nil {
		return Report{}, fmt.Errorf("find specs: %w", err)
	}

	report := Report{Bouncer: suite.Bouncer}
	root := filepath.Dir(suite.TestsDir)
	opts := testrunner.Options{
		TestsDir: suite.TestsDir,
		Policy:   filepath.Join(dir, bouncercfg.FileName),
	}
	for _, file := range files {
		path, err := filepath.Rel(root, file)
		if err != nil {
			path = file
		}
		results, err := testrunner.RunFile(file, opts)
		report.Specs = append(report.Specs, SpecReport{Path: path, Results: results, Err: err})
	}
	return report, nil
}

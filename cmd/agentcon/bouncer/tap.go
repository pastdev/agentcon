package bouncer

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/pastdev/agentcon/pkg/bouncertest"
	"gopkg.in/yaml.v3"
)

// diagnostic is a TAP YAML block. Unset fields are left out.
type diagnostic struct {
	Step      int    `yaml:"step,omitempty"`
	StepName  string `yaml:"step_name,omitempty"`
	Message   string `yaml:"message,omitempty"`
	FilterLog string `yaml:"filter_log,omitempty"`
}

// writeTAP writes report as TAP 14, with one test per spec file and one
// subtest per case.
func writeTAP(w io.Writer, report bouncertest.Report) error {
	var b bytes.Buffer
	b.WriteString("TAP version 14\n")
	for i, spec := range report.Specs {
		n := i + 1
		if spec.Err != nil {
			fmt.Fprintf(&b, "not ok %d - %s\n", n, spec.Path)
			err := writeDiagnostic(&b, "  ", diagnostic{Message: spec.Err.Error()})
			if err != nil {
				return err
			}
			continue
		}
		fmt.Fprintf(&b, "# Subtest: %s\n", spec.Path)
		fmt.Fprintf(&b, "    1..%d\n", len(spec.Results))
		passed := true
		for j, r := range spec.Results {
			if r.Passed {
				fmt.Fprintf(&b, "    ok %d - %s\n", j+1, r.Name)
				continue
			}
			passed = false
			fmt.Fprintf(&b, "    not ok %d - %s\n", j+1, r.Name)
			err := writeDiagnostic(&b, "      ", diagnostic{
				Step:      r.Step,
				StepName:  r.StepName,
				Message:   r.Message,
				FilterLog: r.FilterLog,
			})
			if err != nil {
				return err
			}
		}
		status := "ok"
		if !passed {
			status = "not ok"
		}
		fmt.Fprintf(&b, "%s %d - %s\n", status, n, spec.Path)
	}
	fmt.Fprintf(&b, "1..%d\n", len(report.Specs))
	_, err := w.Write(b.Bytes())
	if err != nil {
		return fmt.Errorf("write tap: %w", err)
	}
	return nil
}

func writeDiagnostic(b *bytes.Buffer, indent string, d diagnostic) error {
	var data bytes.Buffer
	enc := yaml.NewEncoder(&data)
	enc.SetIndent(2)
	err := enc.Encode(d)
	if err != nil {
		return fmt.Errorf("encode tap diagnostic: %w", err)
	}
	b.WriteString(indent + "---\n")
	for _, line := range strings.Split(strings.TrimRight(data.String(), "\n"), "\n") {
		b.WriteString(indent + line + "\n")
	}
	b.WriteString(indent + "...\n")
	return nil
}

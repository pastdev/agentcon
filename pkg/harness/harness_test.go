package harness

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDefaultYAMLIncludesCursor(t *testing.T) {
	docs := DefaultYAML()
	if len(docs) == 0 {
		t.Fatal("expected embedded harness yaml")
	}
	var found bool
	for _, doc := range docs {
		var parsed struct {
			Harnesses map[string]struct {
				Tunnel []string `yaml:"tunnel"`
			} `yaml:"harnesses"`
		}
		err := yaml.Unmarshal(doc, &parsed)
		if err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		spec, ok := parsed.Harnesses[Cursor]
		if !ok {
			continue
		}
		found = true
		if !containsHost(spec.Tunnel, "cursor.com") || !containsHost(spec.Tunnel, "*.cursor.sh") {
			t.Fatalf("cursor tunnel %v", spec.Tunnel)
		}
	}
	if !found {
		t.Fatal("missing harnesses.cursor")
	}
}

func containsHost(hosts []string, want string) bool {
	for _, h := range hosts {
		if strings.EqualFold(h, want) {
			return true
		}
	}
	return false
}

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
	cobracfg "github.com/pastdev/configloader/pkg/cobra"
	cfgldr "github.com/pastdev/configloader/pkg/config"
	"github.com/pastdev/configloader/pkg/xdg"
	"github.com/spf13/cobra"
)

const (
	DirectoryConfigDir = "./agentcon.d"
	SystemConfigDir    = "/etc/agentcon.d"
)

func userConfigDir() string {
	dir, err := xdg.ConfigHome()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "agentcon.d")
}

func resolveOverlayDir(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			if path == "~" {
				path = home
			} else {
				path = filepath.Join(home, path[2:])
			}
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

type Config struct {
	DefaultContext string                 `json:"default_context" yaml:"default_context"`
	Contexts       map[string]ContextSpec `json:"contexts" yaml:"contexts"`
	OverlayDirs    []string               `json:"-" yaml:"-"`
}

// ContextSpec is one named workspace in the agentcon config document.
type ContextSpec struct {
	Image   string             `json:"image" yaml:"image"`
	Root    string             `json:"root" yaml:"root"`
	Bouncer *bouncercfg.Config `json:"bouncer,omitempty" yaml:"bouncer,omitempty"`
}

type Loader struct {
	source      cobracfg.ConfigLoader[Config]
	overlayDirs []string
}

func (l *Loader) AddCommand(root *cobra.Command) {
	l.source.AddSubCommandTo(root)
}

func (l *Loader) AddFlags(root *cobra.Command) {
	unmarshal := valueTemplateUnmarshal()
	flags := l.source.PersistentFlags(root)
	flags.SourceVarP(
		func(path string) cfgldr.SourceLoader {
			l.overlayDirs = append(l.overlayDirs, resolveOverlayDir(path))
			return cfgldr.DirSource{
				Path:      path,
				Unmarshal: unmarshal,
			}
		},
		"config-dir",
		"d",
		"location of one or more config directories")
	flags.SourceVarP(
		func(path string) cfgldr.SourceLoader {
			l.overlayDirs = append(l.overlayDirs, resolveOverlayDir(filepath.Dir(path)))
			return cfgldr.FileSource{
				Path:      path,
				Unmarshal: unmarshal,
			}
		},
		"config",
		"c",
		"location of one or more config files")
}

func (l *Loader) Config() (*Config, error) {
	cfg, err := l.source.Config()
	if err != nil {
		return nil, fmt.Errorf("config load: %w", err)
	}
	cfg.OverlayDirs = append([]string{}, l.overlayDirs...)
	return cfg, nil
}

func valueTemplateUnmarshal() cfgldr.UnmarshalFunc {
	return cfgldr.YamlValueTemplateUnmarshal(cfgldr.NewTemplate(cfgldr.DefaultFuncMap()))
}

func NewLoader() *Loader {
	userDir := userConfigDir()
	overlayDirs := []string{resolveOverlayDir(SystemConfigDir)}
	sources := []cfgldr.SourceLoader{
		cfgldr.DirSource{
			Path:      SystemConfigDir,
			Unmarshal: valueTemplateUnmarshal(),
		},
	}
	if userDir != "" {
		overlayDirs = append(overlayDirs, resolveOverlayDir(userDir))
		sources = append(sources, cfgldr.DirSource{
			Path:      userDir,
			Unmarshal: valueTemplateUnmarshal(),
		})
	}
	overlayDirs = append(overlayDirs, resolveOverlayDir(DirectoryConfigDir))
	sources = append(sources, cfgldr.DirSource{
		Path:      DirectoryConfigDir,
		Unmarshal: valueTemplateUnmarshal(),
	})
	return &Loader{
		overlayDirs: overlayDirs,
		source: cobracfg.ConfigLoader[Config]{
			DefaultSources: cfgldr.Sources[Config]{Sources: sources},
		},
	}
}

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
	"github.com/pastdev/agentcon/pkg/config/urlfile"
	cobracfg "github.com/pastdev/configloader/pkg/cobra"
	cfgldr "github.com/pastdev/configloader/pkg/config"
	"github.com/pastdev/configloader/pkg/xdg"
	"github.com/spf13/cobra"
)

const (
	DirectoryConfigDir = "./agentcon.d"
	SystemConfigDir    = "/etc/agentcon.d"
	defaultDockerfile  = "Dockerfile"
	agentImagePrefix   = "agentcon/"
)

func userConfigDir() string {
	dir, err := xdg.ConfigHome()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "agentcon.d")
}

// urlCacheDir is where urlFile keeps downloads. It is empty when the cache
// home cannot be determined, and urlFile then refuses.
func urlCacheDir() string {
	dir, err := xdg.CacheHome()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "agentcon", "url")
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
	DefaultContext string                        `json:"default_context" yaml:"default_context"`
	Agents         map[string]AgentSpec          `json:"agents,omitempty" yaml:"agents,omitempty"`
	Bouncers       map[string]*bouncercfg.Config `json:"bouncers,omitempty" yaml:"bouncers,omitempty"`
	Contexts       map[string]ContextSpec        `json:"contexts" yaml:"contexts"`
	Sidecar        SidecarSpec                   `json:"sidecar,omitempty" yaml:"sidecar,omitempty"`
	OverlayDirs    []string                      `json:"-" yaml:"-"`
}

// AgentSpec is one named agent image, its binds, and the hosts it must reach.
type AgentSpec struct {
	Image  string      `json:"image,omitempty" yaml:"image,omitempty"`
	Build  *BuildSpec  `json:"build,omitempty" yaml:"build,omitempty"`
	Mounts []MountSpec `json:"mounts,omitempty" yaml:"mounts,omitempty"`
	Tunnel []string    `json:"tunnel,omitempty" yaml:"tunnel,omitempty"`
	// PullPolicy is missing (default), always, or never.
	PullPolicy string `json:"pull_policy,omitempty" yaml:"pull_policy,omitempty"`
}

// BuildSpec is a Compose-style image build.
// Context is relative to the config directory that supplied it, or absolute / ~.
type BuildSpec struct {
	Context    string `json:"context" yaml:"context"`
	Dockerfile string `json:"dockerfile,omitempty" yaml:"dockerfile,omitempty"`
}

// MountSpec is a host-to-container bind for an agent.
// Source is relative to the host home unless it is absolute or starts with ~.
type MountSpec struct {
	Source string `json:"source" yaml:"source"`
	Target string `json:"target" yaml:"target"`
}

// SidecarSpec configures the bouncer sidecar container that run starts.
type SidecarSpec struct {
	// CAFiles are PEM certificate files added to the sidecar's system trust.
	// A path is relative to the host home unless it is absolute or starts with ~.
	CAFiles []string `json:"ca_files,omitempty" yaml:"ca_files,omitempty"`
}

// ContextSpec binds an agent, a workspace root, and an optional bouncer.
type ContextSpec struct {
	Agent   string `json:"agent,omitempty" yaml:"agent,omitempty"`
	Root    string `json:"root" yaml:"root"`
	Bouncer string `json:"bouncer,omitempty" yaml:"bouncer,omitempty"`
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
	funcs := cfgldr.DefaultFuncMap()
	urlfile.New(urlCacheDir()).AddFuncs(funcs)
	return cfgldr.YamlValueTemplateUnmarshal(cfgldr.NewTemplate(funcs))
}

func NewLoader() *Loader {
	userDir := userConfigDir()
	overlayDirs := []string{resolveOverlayDir(SystemConfigDir)}
	unmarshal := valueTemplateUnmarshal()
	sources := []cfgldr.SourceLoader{
		cfgldr.DirSource{
			Path:      SystemConfigDir,
			Unmarshal: unmarshal,
		},
	}
	if userDir != "" {
		overlayDirs = append(overlayDirs, resolveOverlayDir(userDir))
		sources = append(sources, cfgldr.DirSource{
			Path:      userDir,
			Unmarshal: unmarshal,
		})
	}
	overlayDirs = append(overlayDirs, resolveOverlayDir(DirectoryConfigDir))
	sources = append(sources, cfgldr.DirSource{
		Path:      DirectoryConfigDir,
		Unmarshal: unmarshal,
	})
	return &Loader{
		overlayDirs: overlayDirs,
		source: cobracfg.ConfigLoader[Config]{
			DefaultSources: cfgldr.Sources[Config]{Sources: sources},
		},
	}
}

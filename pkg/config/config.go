package config

import (
	"fmt"

	cobracfg "github.com/pastdev/configloader/pkg/cobra"
	cfgldr "github.com/pastdev/configloader/pkg/config"
	"github.com/spf13/cobra"
)

const (
	DirectoryConfigDir = "./agentcon.d"
	SystemConfigDir    = "/etc/agentcon.d"
	UserConfigDir      = "~/.config/agentcon.d"
)

type Config struct {
	DefaultContext string                 `json:"default_context" yaml:"default_context"`
	Contexts       map[string]contextSpec `json:"contexts" yaml:"contexts"`
}

type contextSpec struct {
	Image string `json:"image" yaml:"image"`
	Root  string `json:"root" yaml:"root"`
}

type Loader struct {
	source cobracfg.ConfigLoader[Config]
}

func (l *Loader) AddCommand(root *cobra.Command) {
	l.source.AddSubCommandTo(root)
}

func (l *Loader) AddFlags(root *cobra.Command) {
	l.source.PersistentFlags(root).DirSourceVarP(
		cfgldr.YamlUnmarshal[Config](),
		"config-dir",
		"d",
		"location of one or more config directories")
	l.source.PersistentFlags(root).FileSourceVarP(
		cfgldr.YamlUnmarshal[Config](),
		"config",
		"c",
		"location of one or more config files")
}

func (l *Loader) Config() (*Config, error) {
	cfg, err := l.source.Config()
	if err != nil {
		return nil, fmt.Errorf("config load: %w", err)
	}
	return cfg, nil
}

func NewLoader() *Loader {
	return &Loader{
		source: cobracfg.ConfigLoader[Config]{
			DefaultSources: cfgldr.Sources[Config]{
				cfgldr.DirSource[Config]{
					Path:      SystemConfigDir,
					Unmarshal: cfgldr.YamlUnmarshal[Config](),
				},
				cfgldr.DirSource[Config]{
					Path:      UserConfigDir,
					Unmarshal: cfgldr.YamlUnmarshal[Config](),
				},
				cfgldr.DirSource[Config]{
					Path:      DirectoryConfigDir,
					Unmarshal: cfgldr.YamlUnmarshal[Config](),
				},
			},
		},
	}
}

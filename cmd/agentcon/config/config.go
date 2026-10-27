package config

import (
	pkgcfg "github.com/pastdev/agentcon/pkg/config"
	"github.com/spf13/cobra"
)

func Add(root *cobra.Command, loader *pkgcfg.Loader) {
	loader.AddCommand(root)
	loader.AddFlags(root)
}

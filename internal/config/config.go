package config

import (
	"os"
	"path/filepath"
	"github.com/spf13/pflag"
	"github.com/Vivirinter/rbac-mapper/pkg/export"
)

type Config struct {
	KubeConfig string
	OutputFormat export.Format
	Verbs []string
	Resources []string
	Limit int
}

func New() *Config {
	cfg := &Config{}

	home, _ := os.UserHomeDir()
	defaultKubeconfig := filepath.Join(home, ".kube", "config")

	pflag.StringVar(&cfg.KubeConfig, "kubeconfig", defaultKubeconfig, "path to kubeconfig file")
	pflag.StringVar((*string)(&cfg.OutputFormat), "output-format", string(export.TextFormat), "output format (text|json|yaml)")
	pflag.StringSliceVar(&cfg.Verbs, "verbs", nil, "filter by verbs (comma-separated)")
	pflag.StringSliceVar(&cfg.Resources, "resources", nil, "filter by resources (comma-separated)")
	pflag.IntVar(&cfg.Limit, "limit", 0, "limit the number of results (0 for no limit)")

	pflag.Parse()

	return cfg
}

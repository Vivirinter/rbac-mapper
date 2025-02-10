package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/pflag"
)

type Config struct {
	KubeconfigPath string
	OutputFormat   string
	Verbs         []string
	Resources     []string
	ResultLimit   int
}

func LoadConfig() (*Config, error) {
	var (
		kubeconfig  string
		output      string
		verbs       string
		resources   string
		resultLimit int
	)

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("getting user home dir: %w", err)
	}

	defaultKubeconfig := filepath.Join(home, ".kube", "config")
	if envKubeconfig := os.Getenv("KUBECONFIG"); envKubeconfig != "" {
		defaultKubeconfig = envKubeconfig
	}

	pflag.StringVar(&kubeconfig, "kubeconfig", defaultKubeconfig, "Path to kubeconfig file")
	pflag.StringVar(&output, "output-format", "text", "Output format (text)")
	pflag.StringVar(&verbs, "verbs", "", "Filter by verbs (comma-separated)")
	pflag.StringVar(&resources, "resources", "", "Filter by resources (comma-separated)")
	pflag.IntVar(&resultLimit, "limit", 0, "Limit the number of results (0 for no limit)")
	pflag.Parse()

	cfg := &Config{
		KubeconfigPath: kubeconfig,
		OutputFormat:   output,
		ResultLimit:    resultLimit,
	}

	if verbs != "" {
		cfg.Verbs = strings.Split(verbs, ",")
	}
	if resources != "" {
		cfg.Resources = strings.Split(resources, ",")
	}

	return cfg, nil
}

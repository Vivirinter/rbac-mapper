// Package main provides the entry point for the rbac-mapper tool
package main

import (
	"fmt"
	"os"

	"github.com/Vivirinter/rbac-mapper/internal/config"
	"github.com/Vivirinter/rbac-mapper/pkg/analyzer"
	"github.com/Vivirinter/rbac-mapper/pkg/client"
	"github.com/Vivirinter/rbac-mapper/pkg/export"
)

func main() {
	cfg := config.New()

	k8sClient, err := client.New(cfg.KubeConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating client: %v\n", err)
		os.Exit(1)
	}

	result, err := analyzer.Analyze(k8sClient, analyzer.Options{
		Verbs: cfg.Verbs,
		Resources: cfg.Resources,
		Limit: cfg.Limit,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error analyzing RBAC: %v\n", err)
		os.Exit(1)
	}

	if err := export.Export(*result, cfg.OutputFormat); err != nil {
		fmt.Fprintf(os.Stderr, "Error exporting results: %v\n", err)
		os.Exit(1)
	}
}

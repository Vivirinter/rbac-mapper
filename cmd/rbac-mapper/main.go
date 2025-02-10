// Package main provides the entry point for the rbac-mapper tool
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Vivirinter/rbac-mapper/internal/config"
	"github.com/Vivirinter/rbac-mapper/pkg/analyzer"
	"github.com/Vivirinter/rbac-mapper/pkg/client"
	"github.com/Vivirinter/rbac-mapper/pkg/export"
	"github.com/Vivirinter/rbac-mapper/pkg/filter"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	k8sClient, err := client.NewClient(cfg.KubeconfigPath)
	if err != nil {
		return fmt.Errorf("creating kubernetes client: %w", err)
	}

	f := filter.New(cfg.Verbs, cfg.Resources)

	rbacAnalyzer, err := analyzer.NewAnalyzer(k8sClient, f, cfg.ResultLimit)
	if err != nil {
		return fmt.Errorf("creating analyzer: %w", err)
	}

	// Analyze RBAC configuration
	result, err := rbacAnalyzer.AnalyzeCluster(ctx)
	if err != nil {
		return fmt.Errorf("analyzing cluster: %w", err)
	}

	if err := export.Result(result, cfg.OutputFormat, true); err != nil {
		return fmt.Errorf("exporting result: %w", err)
	}

	return nil
}

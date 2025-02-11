package analyzer

import (
	"context"
	"fmt"
	"github.com/Vivirinter/rbac-mapper/pkg/client"
	"github.com/Vivirinter/rbac-mapper/pkg/filter"
)

const (
	DefaultResultLimit = 1000
	UnlimitedResults   = -1
)

type Options struct {
	Verbs     []string
	Resources []string
	Limit     int
}

type Result struct {
	Roles               map[string][]client.RoleInfo
	ClusterRoles        []client.RoleInfo
	RoleBindings        map[string][]client.BindingInfo
	ClusterRoleBindings []client.BindingInfo
	Stats               Stats
}

type Stats struct {
	TotalNamespaces     int
	NamespacesWithRoles int
	TotalRoles          int
	TotalClusterRoles   int
	TotalBindings       int
}

func Analyze(c *client.Client, opts Options) (*Result, error) {
	result := &Result{
		Roles:        make(map[string][]client.RoleInfo),
		RoleBindings: make(map[string][]client.BindingInfo),
	}

	namespaces, err := c.ListNamespaces(context.Background())
	if err != nil {
		return nil, fmt.Errorf("listing namespaces: %w", err)
	}

	clusterRoles, err := c.ListClusterRoles(context.Background())
	if err != nil {
		return nil, fmt.Errorf("listing cluster roles: %w", err)
	}
	result.ClusterRoles = analyzeRoles(clusterRoles, opts)

	clusterBindings, err := c.ListClusterRoleBindings(context.Background())
	if err != nil {
		return nil, fmt.Errorf("listing cluster bindings: %w", err)
	}
	result.ClusterRoleBindings = analyzeBindings(clusterBindings, opts)

	for _, ns := range namespaces {
		roles, err := c.ListRoles(context.Background(), ns)
		if err != nil {
			return nil, fmt.Errorf("listing roles for namespace %s: %w", ns, err)
		}

		analyzedRoles := analyzeRoles(roles, opts)
		if len(analyzedRoles) > 0 {
			result.Roles[ns] = analyzedRoles
		}

		bindings, err := c.ListRoleBindings(context.Background(), ns)
		if err != nil {
			return nil, fmt.Errorf("listing bindings for namespace %s: %w", ns, err)
		}

		analyzedBindings := analyzeBindings(bindings, opts)
		if len(analyzedBindings) > 0 {
			result.RoleBindings[ns] = analyzedBindings
		}
	}

	result.Stats = calculateStats(result)
	return result, nil
}

func analyzeRoles(roles []client.RoleInfo, opts Options) []client.RoleInfo {
	if len(opts.Verbs) == 0 && len(opts.Resources) == 0 {
		return roles
	}

	f := filter.New(opts.Verbs, opts.Resources)
	filtered := make([]client.RoleInfo, 0, len(roles))
	for _, role := range roles {
		if f.MatchRole(role) {
			filtered = append(filtered, role)
		}
	}
	return filtered
}

func analyzeBindings(bindings []client.BindingInfo, opts Options) []client.BindingInfo {
	if opts.Limit == 0 {
		return bindings
	}

	if len(bindings) > opts.Limit {
		return bindings[:opts.Limit]
	}
	return bindings
}

func calculateStats(result *Result) Stats {
	stats := Stats{
		TotalNamespaces:   len(result.Roles),
		TotalClusterRoles: len(result.ClusterRoles),
	}

	for _, roles := range result.Roles {
		if len(roles) > 0 {
			stats.NamespacesWithRoles++
		}
		stats.TotalRoles += len(roles)
	}

	stats.TotalBindings = len(result.ClusterRoleBindings)
	for _, bindings := range result.RoleBindings {
		stats.TotalBindings += len(bindings)
	}

	return stats
}

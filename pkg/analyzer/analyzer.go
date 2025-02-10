package analyzer

import (
	"context"
	"fmt"
	"github.com/Vivirinter/rbac-mapper/pkg/client"
)

const (
	DefaultResultLimit = 1000
	UnlimitedResults  = -1
)

type Options struct {
	Verbs     []string
	Resources []string
	Limit     int
}

type Result struct {
	Roles               map[string][]client.RoleInfo
	ClusterRoles       []client.RoleInfo
	RoleBindings       map[string][]client.BindingInfo
	ClusterRoleBindings []client.BindingInfo
	Stats              Stats
}

type Stats struct {
	TotalNamespaces     int
	NamespacesWithRoles int
	TotalRoles         int
	TotalClusterRoles  int
	TotalBindings      int
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

	result.ClusterRoles = make([]client.RoleInfo, 0, 10) // Most clusters have <10 ClusterRoles
	clusterRoles, err := c.ListClusterRoles(context.Background())
	if err != nil {
		return nil, fmt.Errorf("listing cluster roles: %w", err)
	}
	result.ClusterRoles = filterRoles(clusterRoles, opts)

	result.ClusterRoleBindings = make([]client.BindingInfo, 0, len(result.ClusterRoles))
	clusterBindings, err := c.ListClusterRoleBindings(context.Background())
	if err != nil {
		return nil, fmt.Errorf("listing cluster bindings: %w", err)
	}
	result.ClusterRoleBindings = filterBindings(clusterBindings, opts)

	for _, ns := range namespaces {
		roles, err := c.ListRoles(context.Background(), ns)
		if err != nil {
			return nil, fmt.Errorf("listing roles for namespace %s: %w", ns, err)
		}

		filteredRoles := filterRoles(roles, opts)
		if len(filteredRoles) > 0 {
			result.Roles[ns] = filteredRoles
		}

		bindings, err := c.ListRoleBindings(context.Background(), ns)
		if err != nil {
			return nil, fmt.Errorf("listing bindings for namespace %s: %w", ns, err)
		}

		filteredBindings := filterBindings(bindings, opts)
		if len(filteredBindings) > 0 {
			result.RoleBindings[ns] = filteredBindings
		}
	}

	result.Stats = calculateStats(result)
	return result, nil
}

func filterRoles(roles []client.RoleInfo, opts Options) []client.RoleInfo {
	if len(opts.Verbs) == 0 && len(opts.Resources) == 0 {
		return roles
	}

	filtered := make([]client.RoleInfo, 0, len(roles))
	for _, role := range roles {
		if matchesFilters(role, opts) {
			filtered = append(filtered, role)
		}
	}
	return filtered
}

func filterBindings(bindings []client.BindingInfo, opts Options) []client.BindingInfo {
	if opts.Limit == 0 {
		return bindings
	}

	if len(bindings) > opts.Limit {
		return bindings[:opts.Limit]
	}
	return bindings
}

func matchesFilters(role client.RoleInfo, opts Options) bool {
	for _, rule := range role.Rules {
		if matchesVerbs(rule.Verbs, opts.Verbs) && matchesResources(rule.Resources, opts.Resources) {
			return true
		}
	}
	return false
}

func matchesVerbs(ruleVerbs, filterVerbs []string) bool {
	if len(filterVerbs) == 0 {
		return true
	}

	verbMap := make(map[string]struct{}, len(ruleVerbs))
	for _, verb := range ruleVerbs {
		verbMap[verb] = struct{}{}
	}

	for _, verb := range filterVerbs {
		if _, ok := verbMap[verb]; ok {
			return true
		}
	}
	return false
}

func matchesResources(ruleResources, filterResources []string) bool {
	if len(filterResources) == 0 {
		return true
	}

	resourceMap := make(map[string]struct{}, len(ruleResources))
	for _, resource := range ruleResources {
		resourceMap[resource] = struct{}{}
	}

	for _, resource := range filterResources {
		if _, ok := resourceMap[resource]; ok {
			return true
		}
	}
	return false
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

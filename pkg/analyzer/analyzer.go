package analyzer

import (
	"context"
	"fmt"
	"sort"

	"github.com/Vivirinter/rbac-mapper/pkg/client"
	"github.com/Vivirinter/rbac-mapper/pkg/filter"
)

const (
	DefaultResultLimit = 1000
	UnlimitedResults  = -1
)

type Stats struct {
	TotalNamespaces     int
	NamespacesWithRoles int
	TotalRoles         int
	TotalClusterRoles  int
	TotalBindings      int
}

type AnalysisResult struct {
	NamespaceRoles    map[string][]client.RoleInfo    `json:"namespaceRoles" yaml:"namespaceRoles"`
	ClusterRoles     []client.RoleInfo               `json:"clusterRoles" yaml:"clusterRoles"`
	NamespaceBindings map[string][]client.BindingInfo `json:"namespaceBindings" yaml:"namespaceBindings"`
	ClusterBindings   []client.BindingInfo           `json:"clusterBindings" yaml:"clusterBindings"`
	Stats            Stats                           `json:"stats" yaml:"stats"`
	Truncated        bool                           `json:"truncated" yaml:"truncated"`
}

type Analyzer struct {
	client      *client.Client
	filter      *filter.Filter
	resultLimit int
}

func NewAnalyzer(client *client.Client, filter *filter.Filter, resultLimit int) (*Analyzer, error) {
	if client == nil {
		return nil, fmt.Errorf("client cannot be nil")
	}

	limit := resultLimit
	if limit == 0 {
		limit = DefaultResultLimit
	}

	return &Analyzer{
		client:      client,
		filter:      filter,
		resultLimit: limit,
	}, nil
}

func (a *Analyzer) AnalyzeCluster(ctx context.Context) (*AnalysisResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	namespaces, err := a.client.GetNamespaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting namespaces: %w", err)
	}

	result := &AnalysisResult{
		NamespaceRoles:    make(map[string][]client.RoleInfo),
		NamespaceBindings: make(map[string][]client.BindingInfo),
	}

	result.Stats.TotalNamespaces = len(namespaces)

	if err := a.collectAllRoles(ctx, namespaces, result); err != nil {
		return nil, fmt.Errorf("collecting roles: %w", err)
	}

	if err := a.collectAllBindings(ctx, namespaces, result); err != nil {
		return nil, fmt.Errorf("collecting bindings: %w", err)
	}

	return result, nil
}

func (a *Analyzer) collectAllRoles(ctx context.Context, namespaces []string, result *AnalysisResult) error {
	if err := a.collectNamespaceRoles(ctx, namespaces, result); err != nil {
		return fmt.Errorf("collecting namespace roles: %w", err)
	}

	if err := a.collectClusterRoles(ctx, result); err != nil {
		return fmt.Errorf("collecting cluster roles: %w", err)
	}

	return nil
}

func (a *Analyzer) collectNamespaceRoles(ctx context.Context, namespaces []string, result *AnalysisResult) error {
	totalRoles := 0
	for _, ns := range namespaces {
		roles, err := a.client.GetRoles(ctx, ns)
		if err != nil {
			return fmt.Errorf("getting roles for namespace %s: %w", ns, err)
		}

		filteredRoles := a.filterRoles(roles, totalRoles)
		if len(filteredRoles) > 0 {
			result.NamespaceRoles[ns] = filteredRoles
			totalRoles += len(filteredRoles)
			result.Stats.NamespacesWithRoles++
		}

		if a.shouldTruncate(totalRoles) {
			result.Truncated = true
			break
		}
	}

	result.Stats.TotalRoles = totalRoles
	return nil
}

func (a *Analyzer) collectClusterRoles(ctx context.Context, result *AnalysisResult) error {
	roles, err := a.client.GetClusterRoles(ctx)
	if err != nil {
		return fmt.Errorf("getting cluster roles: %w", err)
	}

	filteredRoles := a.filterRoles(roles, 0)
	result.ClusterRoles = filteredRoles
	result.Stats.TotalClusterRoles = len(filteredRoles)

	return nil
}

func (a *Analyzer) filterRoles(roles []client.RoleInfo, currentTotal int) []client.RoleInfo {
	var filtered []client.RoleInfo
	for _, role := range roles {
		if a.shouldTruncate(currentTotal + len(filtered)) {
			break
		}
		if a.filter == nil || a.filter.MatchRole(role) {
			filtered = append(filtered, role)
		}
	}
	return filtered
}

func (a *Analyzer) shouldTruncate(count int) bool {
	return a.resultLimit != UnlimitedResults && count >= a.resultLimit
}

func (a *Analyzer) collectAllBindings(ctx context.Context, namespaces []string, result *AnalysisResult) error {
	if err := a.collectBindings(ctx, namespaces, result); err != nil {
		return fmt.Errorf("collecting role bindings: %w", err)
	}

	if err := a.collectClusterBindings(ctx, result); err != nil {
		return fmt.Errorf("collecting cluster role bindings: %w", err)
	}

	return nil
}

func (a *Analyzer) collectBindings(ctx context.Context, namespaces []string, result *AnalysisResult) error {
	totalBindings := 0
	for _, ns := range namespaces {
		bindings, err := a.client.GetBindings(ctx, ns)
		if err != nil {
			return fmt.Errorf("getting bindings for namespace %s: %w", ns, err)
		}

		filteredBindings := make([]client.BindingInfo, 0)
		for _, binding := range bindings {
			if a.shouldTruncate(totalBindings + len(filteredBindings)) {
				result.Truncated = true
				break
			}
			if a.filter == nil || a.filter.MatchBinding(binding) {
				filteredBindings = append(filteredBindings, binding)
			}
		}

		sort.Slice(filteredBindings, func(i, j int) bool {
			return filteredBindings[i].Name < filteredBindings[j].Name
		})

		if len(filteredBindings) > 0 {
			result.NamespaceBindings[ns] = filteredBindings
			totalBindings += len(filteredBindings)
		}

		if a.shouldTruncate(totalBindings) {
			result.Truncated = true
			break
		}
	}
	result.Stats.TotalBindings = totalBindings
	return nil
}

func (a *Analyzer) collectClusterBindings(ctx context.Context, result *AnalysisResult) error {
	bindings, err := a.client.GetClusterBindings(ctx)
	if err != nil {
		return fmt.Errorf("getting cluster bindings: %w", err)
	}

	filteredBindings := make([]client.BindingInfo, 0)
	for _, binding := range bindings {
		if a.shouldTruncate(result.Stats.TotalBindings + len(filteredBindings)) {
			result.Truncated = true
			break
		}
		if a.filter == nil || a.filter.MatchBinding(binding) {
			filteredBindings = append(filteredBindings, binding)
		}
	}

	sort.Slice(filteredBindings, func(i, j int) bool {
		return filteredBindings[i].Name < filteredBindings[j].Name
	})

	result.ClusterBindings = filteredBindings
	result.Stats.TotalBindings += len(filteredBindings)
	return nil
}

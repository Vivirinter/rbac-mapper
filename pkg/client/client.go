package client

import (
	"context"
	"fmt"
	"k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	ErrInvalidKubeconfig = fmt.Errorf("invalid kubeconfig")
	ErrClientConnection  = fmt.Errorf("failed to connect to cluster")
)

type Client struct {
	clientset *kubernetes.Clientset
}

func New(kubeconfigPath string) (*Client, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKubeconfig, err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrClientConnection, err)
	}

	return &Client{clientset: clientset}, nil
}

func (c *Client) ListNamespaces(ctx context.Context) ([]string, error) {
	namespaces, err := c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing namespaces: %w", err)
	}

	result := make([]string, 0, len(namespaces.Items))
	for _, ns := range namespaces.Items {
		result = append(result, ns.Name)
	}
	return result, nil
}

func (c *Client) ListRoles(ctx context.Context, namespace string) ([]RoleInfo, error) {
	roles, err := c.clientset.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing roles in namespace %s: %w", namespace, err)
	}

	result := make([]RoleInfo, 0, len(roles.Items))
	for _, role := range roles.Items {
		result = append(result, convertRole(role))
	}
	return result, nil
}

func (c *Client) ListClusterRoles(ctx context.Context) ([]RoleInfo, error) {
	roles, err := c.clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing cluster roles: %w", err)
	}

	result := make([]RoleInfo, 0, len(roles.Items))
	for _, role := range roles.Items {
		result = append(result, convertClusterRole(role))
	}
	return result, nil
}

func (c *Client) ListRoleBindings(ctx context.Context, namespace string) ([]BindingInfo, error) {
	bindings, err := c.clientset.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing role bindings in namespace %s: %w", namespace, err)
	}

	result := make([]BindingInfo, 0, len(bindings.Items))
	for _, binding := range bindings.Items {
		result = append(result, convertRoleBinding(binding))
	}
	return result, nil
}

func (c *Client) ListClusterRoleBindings(ctx context.Context) ([]BindingInfo, error) {
	bindings, err := c.clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing cluster role bindings: %w", err)
	}

	result := make([]BindingInfo, 0, len(bindings.Items))
	for _, binding := range bindings.Items {
		result = append(result, convertClusterRoleBinding(binding))
	}
	return result, nil
}

func convertRole(role v1.Role) RoleInfo {
	return RoleInfo{
		Name:      role.Name,
		Namespace: role.Namespace,
		Kind:      KindRole,
		Rules:     convertRules(role.Rules),
	}
}

func convertClusterRole(role v1.ClusterRole) RoleInfo {
	return RoleInfo{
		Name:      role.Name,
		Namespace: "",
		Kind:      KindClusterRole,
		Rules:     convertRules(role.Rules),
	}
}

func convertRules(rules []v1.PolicyRule) []RuleInfo {
	result := make([]RuleInfo, 0, len(rules))
	for _, rule := range rules {
		resources := make([]string, 0, len(rule.Resources)*len(rule.APIGroups))
		if len(rule.APIGroups) > 0 {
			for _, group := range rule.APIGroups {
				for _, resource := range rule.Resources {
					if group == "" {
						resources = append(resources, resource)
					} else {
						resources = append(resources, fmt.Sprintf("%s/%s", group, resource))
					}
				}
			}
		} else {
			resources = append(resources, rule.Resources...)
		}

		result = append(result, RuleInfo{
			Resources: resources,
			Verbs:     rule.Verbs,
		})
	}
	return result
}

func convertRoleBinding(binding v1.RoleBinding) BindingInfo {
	return BindingInfo{
		Name:      binding.Name,
		Namespace: binding.Namespace,
		Kind:      KindRoleBinding,
		RoleRef: RoleRef{
			Kind: binding.RoleRef.Kind,
			Name: binding.RoleRef.Name,
		},
		Subjects: convertSubjects(binding.Subjects),
	}
}

func convertClusterRoleBinding(binding v1.ClusterRoleBinding) BindingInfo {
	return BindingInfo{
		Name:      binding.Name,
		Namespace: "",
		Kind:      KindClusterRoleBinding,
		RoleRef: RoleRef{
			Kind: binding.RoleRef.Kind,
			Name: binding.RoleRef.Name,
		},
		Subjects: convertSubjects(binding.Subjects),
	}
}

func convertSubjects(subjects []v1.Subject) []Subject {
	result := make([]Subject, 0, len(subjects))
	for _, subject := range subjects {
		result = append(result, Subject{
			Kind:      subject.Kind,
			Name:      subject.Name,
			Namespace: subject.Namespace,
		})
	}
	return result
}

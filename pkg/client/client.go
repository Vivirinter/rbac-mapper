package client

import (
	"context"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type Client struct {
	clientset *kubernetes.Clientset
}

func NewClient(kubeconfigPath string) (*Client, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &Client{clientset: clientset}, nil
}

func (c *Client) GetNamespaces(ctx context.Context) ([]string, error) {
	namespaces, err := c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	namespaceList := make([]string, 0, len(namespaces.Items))
	for _, ns := range namespaces.Items {
		namespaceList = append(namespaceList, ns.Name)
	}

	return namespaceList, nil
}

func (c *Client) GetRoles(ctx context.Context, namespace string) ([]RoleInfo, error) {
	roles, err := c.clientset.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	roleInfos := make([]RoleInfo, 0, len(roles.Items))
	for _, role := range roles.Items {
		roleInfos = append(roleInfos, convertRole(role))
	}

	return roleInfos, nil
}

func (c *Client) GetClusterRoles(ctx context.Context) ([]RoleInfo, error) {
	clusterRoles, err := c.clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	roleInfos := make([]RoleInfo, 0, len(clusterRoles.Items))
	for _, role := range clusterRoles.Items {
		roleInfos = append(roleInfos, convertClusterRole(role))
	}

	return roleInfos, nil
}

func (c *Client) GetBindings(ctx context.Context, namespace string) ([]BindingInfo, error) {
	roleBindings, err := c.clientset.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	bindingInfos := make([]BindingInfo, 0, len(roleBindings.Items))
	for _, binding := range roleBindings.Items {
		bindingInfos = append(bindingInfos, convertRoleBinding(binding))
	}

	return bindingInfos, nil
}

func (c *Client) GetClusterBindings(ctx context.Context) ([]BindingInfo, error) {
	clusterBindings, err := c.clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	bindingInfos := make([]BindingInfo, 0, len(clusterBindings.Items))
	for _, binding := range clusterBindings.Items {
		bindingInfos = append(bindingInfos, convertClusterRoleBinding(binding))
	}

	return bindingInfos, nil
}

func convertRole(role rbacv1.Role) RoleInfo {
	return RoleInfo{
		Name:      role.Name,
		Namespace: role.Namespace,
		Kind:      KindRole,
		Rules:     convertRules(role.Rules),
	}
}

func convertClusterRole(role rbacv1.ClusterRole) RoleInfo {
	return RoleInfo{
		Name:      role.Name,
		Namespace: "",
		Kind:      KindClusterRole,
		Rules:     convertRules(role.Rules),
	}
}

func convertRules(rules []rbacv1.PolicyRule) []RuleInfo {
	ruleInfos := make([]RuleInfo, 0, len(rules))
	for _, rule := range rules {
		ruleInfos = append(ruleInfos, RuleInfo{
			Resources: rule.Resources,
			Verbs:     rule.Verbs,
		})
	}
	return ruleInfos
}

func convertRoleBinding(binding rbacv1.RoleBinding) BindingInfo {
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

func convertClusterRoleBinding(binding rbacv1.ClusterRoleBinding) BindingInfo {
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

func convertSubjects(subjects []rbacv1.Subject) []Subject {
	subjectInfos := make([]Subject, 0, len(subjects))
	for _, subject := range subjects {
		subjectInfos = append(subjectInfos, Subject{
			Kind:      subject.Kind,
			Name:      subject.Name,
			Namespace: subject.Namespace,
		})
	}
	return subjectInfos
}

package client

type RoleKind string
type BindingKind string

const (
	KindRole        RoleKind = "Role"
	KindClusterRole RoleKind = "ClusterRole"

	KindRoleBinding        BindingKind = "RoleBinding"
	KindClusterRoleBinding BindingKind = "ClusterRoleBinding"
)

type RoleInfo struct {
	Name      string
	Namespace string
	Rules     []RuleInfo
	Kind      RoleKind
}

type RuleInfo struct {
	Resources []string
	Verbs     []string
}

type BindingInfo struct {
	Name      string
	Namespace string
	Kind      BindingKind
	RoleRef   RoleRef
	Subjects  []Subject
}

type RoleRef struct {
	Kind string
	Name string
}

type Subject struct {
	Kind      string
	Name      string
	Namespace string
}

package client

type RoleInfo struct {
	Name      string
	Namespace string
	Rules     []RuleInfo
	Kind      RoleKind
}

type RoleKind string

const (
	KindRole        RoleKind = "Role"
	KindClusterRole RoleKind = "ClusterRole"
)

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

type BindingKind string

const (
	KindRoleBinding        BindingKind = "RoleBinding"
	KindClusterRoleBinding BindingKind = "ClusterRoleBinding"
)

type RoleRef struct {
	Kind string
	Name string
}

type Subject struct {
	Kind      string
	Name      string
	Namespace string
}

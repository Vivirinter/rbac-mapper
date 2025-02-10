package formatter

import (
	"fmt"
	"strings"

	"github.com/Vivirinter/rbac-mapper/pkg/analyzer"
	"github.com/Vivirinter/rbac-mapper/pkg/client"
)

const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorRed    = "\033[31m"

	indent = "  "
)

type Formatter struct {
	useColors bool
	sb        strings.Builder
}

func NewFormatter(useColors bool) *Formatter {
	return &Formatter{useColors: useColors}
}

func (f *Formatter) FormatAnalysis(result *analyzer.AnalysisResult) string {
	f.sb.Reset()
	f.writeHeader()
	f.writeNamespaceRoles(result.NamespaceRoles)
	f.writeClusterRoles(result.ClusterRoles)
	f.writeBindings(result.NamespaceBindings, result.ClusterBindings)
	f.writeStats(result.Stats)
	return f.sb.String()
}

func (f *Formatter) writeHeader() {
	f.writeLine(f.colored(colorCyan, "=== RBAC Permissions Analysis ===\n"))
}

func (f *Formatter) writeNamespaceRoles(roles map[string][]client.RoleInfo) {
	f.writeLine(f.colored(colorCyan, "=== Namespace Roles ==="))
	for ns, nsRoles := range roles {
		f.writeNamespaceSection(ns, nsRoles)
	}
	f.writeLine("")
}

func (f *Formatter) writeClusterRoles(roles []client.RoleInfo) {
	f.writeLine(f.colored(colorCyan, "=== Cluster Roles ==="))
	if len(roles) == 0 {
		f.writeLine("No cluster roles found")
		return
	}

	for _, role := range roles {
		f.writeRole(role)
	}
	f.writeLine("")
}

func (f *Formatter) writeBindings(nsBindings map[string][]client.BindingInfo, clusterBindings []client.BindingInfo) {
	f.writeLine(f.colored(colorCyan, "=== Role Bindings ==="))
	
	f.writeLine(f.colored(colorBlue, "\n🔹 Cluster Role Bindings:"))
	for _, binding := range clusterBindings {
		f.writeBinding(binding)
	}

	f.writeLine(f.colored(colorBlue, "\n🔹 Namespace Role Bindings:"))
	for ns, bindings := range nsBindings {
		if len(bindings) > 0 {
			f.writeLine(f.colored(colorGreen, fmt.Sprintf("\nNamespace: %s", ns)))
			for _, binding := range bindings {
				f.writeBinding(binding)
			}
		}
	}
	f.writeLine("")
}

func (f *Formatter) writeNamespaceSection(namespace string, roles []client.RoleInfo) {
	if len(roles) == 0 {
		f.writeLine(f.colored(colorBlue, fmt.Sprintf("🔹 Namespace: %s (no roles)", namespace)))
		return
	}

	f.writeLine(f.colored(colorBlue, fmt.Sprintf("🔹 Namespace: %s", namespace)))
	for _, role := range roles {
		f.writeRole(role)
	}
}

func (f *Formatter) writeRole(role client.RoleInfo) {
	f.writeLine(f.colored(colorGreen, fmt.Sprintf("%s├─ %s: %s", indent, role.Kind, role.Name)))
	
	for _, rule := range role.Rules {
		f.writeRule(rule)
	}
	f.writeLine(indent + "│")
}

func (f *Formatter) writeRule(rule client.RuleInfo) {
	resources := strings.Join(rule.Resources, ", ")
	verbs := strings.Join(rule.Verbs, ", ")
	
	f.writeLine(f.colored(colorYellow, fmt.Sprintf("%s│  ├─ Resources: ", indent)) + resources)
	f.writeLine(f.colored(colorPurple, fmt.Sprintf("%s│  └─ Actions: ", indent)) + verbs)
}

func (f *Formatter) writeBinding(binding client.BindingInfo) {
	f.writeLine(f.colored(colorGreen, fmt.Sprintf("%s├─ %s: %s", indent, binding.Kind, binding.Name)))
	f.writeLine(f.colored(colorYellow, fmt.Sprintf("%s│  ├─ References: ", indent)) + 
		fmt.Sprintf("%s/%s", binding.RoleRef.Kind, binding.RoleRef.Name))
	
	f.writeLine(f.colored(colorPurple, fmt.Sprintf("%s│  └─ Subjects:", indent)))
	for _, subject := range binding.Subjects {
		ns := subject.Namespace
		if ns == "" {
			ns = "<cluster-wide>"
		}
		f.writeLine(fmt.Sprintf("%s│     ├─ %s: %s (%s)", indent, subject.Kind, subject.Name, ns))
	}
	f.writeLine(indent + "│")
}

func (f *Formatter) writeStats(stats analyzer.Stats) {
	f.writeLine(f.colored(colorCyan, "=== Summary ==="))
	f.writeLine(fmt.Sprintf("Total namespaces: %d", stats.TotalNamespaces))
	f.writeLine(fmt.Sprintf("Namespaces with roles: %d", stats.NamespacesWithRoles))
	f.writeLine(fmt.Sprintf("Total namespace roles: %d", stats.TotalRoles))
	f.writeLine(fmt.Sprintf("Total cluster roles: %d", stats.TotalClusterRoles))
	f.writeLine(fmt.Sprintf("Total bindings: %d", stats.TotalBindings))
}

func (f *Formatter) colored(color, text string) string {
	if !f.useColors {
		return text
	}
	return color + text + colorReset
}

func (f *Formatter) writeLine(text string) {
	f.sb.WriteString(text + "\n")
}

package formatter

import (
	"fmt"
	"strings"

	"github.com/Vivirinter/rbac-mapper/pkg/analyzer"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

const (
	minColWidth = 20
	maxColWidth = 35
	padding     = 1
)

var (
	baseStyle = lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("240"))

	titleStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("99"))

	headerStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("240"))
)

type tableConfig struct {
	title   string
	headers []string
	rows    []table.Row
	width   int
}

func getTerminalWidth() int {
	width, _, err := term.GetSize(0)
	if err != nil {
		return 120
	}
	return width
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func createTable(cfg tableConfig) string {
	if len(cfg.rows) == 0 {
		return baseStyle.Render("No data available")
	}

	numCols := len(cfg.headers)
	colWidths := make([]int, numCols)

	for i, header := range cfg.headers {
		colWidths[i] = len(header)
	}

	for _, row := range cfg.rows {
		for i, cell := range row {
			if len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}

	totalWidth := 0
	for i := range colWidths {
		if colWidths[i] < minColWidth {
			colWidths[i] = minColWidth
		}
		if colWidths[i] > maxColWidth {
			colWidths[i] = maxColWidth
		}
		totalWidth += colWidths[i]
	}

	if totalWidth > cfg.width && cfg.width > 0 {
		ratio := float64(cfg.width-padding*numCols) / float64(totalWidth)
		for i := range colWidths {
			colWidths[i] = int(float64(colWidths[i]) * ratio)
			if colWidths[i] < minColWidth {
				colWidths[i] = minColWidth
			}
		}
	}

	columns := make([]table.Column, len(cfg.headers))
	for i, header := range cfg.headers {
		columns[i] = table.Column{
			Title: truncateString(header, colWidths[i]),
			Width: colWidths[i],
		}
	}

	processedRows := make([]table.Row, len(cfg.rows))
	for i, row := range cfg.rows {
		processedRow := make(table.Row, len(row))
		for j, cell := range row {
			processedRow[j] = truncateString(cell, colWidths[j])
		}
		processedRows[i] = processedRow
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(processedRows),
		table.WithFocused(false),
		table.WithHeight(len(processedRows)),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		Bold(true)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("212")).
		Bold(true)

	t.SetStyles(s)

	var sb strings.Builder
	sb.WriteString(titleStyle.Render(cfg.title))
	sb.WriteString("\n")
	sb.WriteString(baseStyle.Render(t.View()))
	sb.WriteString("\n")
	return sb.String()
}

func FormatRoles(result *analyzer.Result) string {
	var sb strings.Builder

	// Cluster Roles
	rows := make([]table.Row, 0)
	for _, role := range result.ClusterRoles {
		for _, rule := range role.Rules {
			rows = append(rows, table.Row{
				role.Name,
				strings.Join(rule.Resources, ", "),
				strings.Join(rule.Verbs, ", "),
			})
		}
	}
	sb.WriteString(createTable(tableConfig{
		title:   "Cluster Roles",
		headers: []string{"Role", "Resources", "Verbs"},
		rows:    rows,
		width:   getTerminalWidth(),
	}))

	rows = make([]table.Row, 0)
	for namespace, roles := range result.Roles {
		for _, role := range roles {
			for _, rule := range role.Rules {
				rows = append(rows, table.Row{
					namespace,
					role.Name,
					strings.Join(rule.Resources, ", "),
					strings.Join(rule.Verbs, ", "),
				})
			}
		}
	}
	sb.WriteString(createTable(tableConfig{
		title:   "Namespace Roles",
		headers: []string{"Namespace", "Role", "Resources", "Verbs"},
		rows:    rows,
		width:   getTerminalWidth(),
	}))

	return sb.String()
}

func FormatBindings(result *analyzer.Result) string {
	var sb strings.Builder

	rows := make([]table.Row, 0)
	for _, binding := range result.ClusterRoleBindings {
		for _, subject := range binding.Subjects {
			rows = append(rows, table.Row{
				truncateString(binding.Name, maxColWidth),
				truncateString(binding.RoleRef.Kind+"/"+binding.RoleRef.Name, maxColWidth),
				truncateString(subject.Kind+": "+subject.Name, maxColWidth),
				subject.Namespace,
			})
		}
	}
	sb.WriteString(createTable(tableConfig{
		title:   "Cluster Role Bindings",
		headers: []string{"Binding", "RoleRef", "Subject", "Namespace"},
		rows:    rows,
		width:   getTerminalWidth(),
	}))

	rows = make([]table.Row, 0)
	for namespace, bindings := range result.RoleBindings {
		for _, binding := range bindings {
			for _, subject := range binding.Subjects {
				rows = append(rows, table.Row{
					namespace,
					truncateString(binding.Name, maxColWidth),
					truncateString(binding.RoleRef.Kind+"/"+binding.RoleRef.Name, maxColWidth),
					truncateString(subject.Kind+": "+subject.Name, maxColWidth),
					subject.Namespace,
				})
			}
		}
	}
	sb.WriteString(createTable(tableConfig{
		title:   "Role Bindings",
		headers: []string{"Namespace", "Binding", "RoleRef", "Subject", "Subject Namespace"},
		rows:    rows,
		width:   getTerminalWidth(),
	}))

	return sb.String()
}

func FormatSummary(result *analyzer.Result) string {
	stats := analyzer.Stats{
		TotalClusterRoles:   len(result.ClusterRoles),
		TotalBindings:       len(result.ClusterRoleBindings),
		NamespacesWithRoles: len(result.Roles),
	}

	for _, roles := range result.Roles {
		stats.TotalRoles += len(roles)
	}

	rows := []table.Row{
		{"Cluster Roles", fmt.Sprintf("%d", stats.TotalClusterRoles)},
		{"Cluster Role Bindings", fmt.Sprintf("%d", stats.TotalBindings)},
		{"Namespaces with Roles", fmt.Sprintf("%d", stats.NamespacesWithRoles)},
		{"Namespace Roles", fmt.Sprintf("%d", stats.TotalRoles)},
	}

	return createTable(tableConfig{
		title:   "Summary",
		headers: []string{"Type", "Count"},
		rows:    rows,
		width:   getTerminalWidth(),
	})
}

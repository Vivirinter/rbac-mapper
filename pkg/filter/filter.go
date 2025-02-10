package filter

import (
	"strings"

	"github.com/Vivirinter/rbac-mapper/pkg/client"
)

type Filter struct {
	verbs     []string
	resources []string
}

func New(verbs, resources []string) *Filter {
	return &Filter{
		verbs:     verbs,
		resources: resources,
	}
}

func (f *Filter) MatchRole(role client.RoleInfo) bool {
	if f == nil || (len(f.verbs) == 0 && len(f.resources) == 0) {
		return true
	}

	for _, rule := range role.Rules {
		if f.matchRule(rule) {
			return true
		}
	}
	return false
}

func (f *Filter) matchRule(rule client.RuleInfo) bool {
	return f.matchVerbs(rule.Verbs) && f.matchResources(rule.Resources)
}

func (f *Filter) matchVerbs(ruleVerbs []string) bool {
	if len(f.verbs) == 0 {
		return true
	}

	for _, verb := range f.verbs {
		for _, ruleVerb := range ruleVerbs {
			if strings.EqualFold(verb, ruleVerb) {
				return true
			}
		}
	}
	return false
}

func (f *Filter) matchResources(ruleResources []string) bool {
	if len(f.resources) == 0 {
		return true
	}

	for _, resource := range f.resources {
		for _, ruleResource := range ruleResources {
			if strings.EqualFold(resource, ruleResource) {
				return true
			}
		}
	}
	return false
}

func (f *Filter) MatchBinding(binding client.BindingInfo) bool {
	return true
}

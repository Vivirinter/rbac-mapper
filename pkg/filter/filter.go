package filter

import (
	"strings"

	"github.com/Vivirinter/rbac-mapper/pkg/client"
)

type Filter struct {
	verbMap     map[string]struct{}
	resourceMap map[string]struct{}
}

func New(verbs, resources []string) *Filter {
	f := &Filter{
		verbMap:     make(map[string]struct{}, len(verbs)),
		resourceMap: make(map[string]struct{}, len(resources)),
	}

	for _, verb := range verbs {
		f.verbMap[strings.ToLower(verb)] = struct{}{}
	}
	for _, resource := range resources {
		f.resourceMap[strings.ToLower(resource)] = struct{}{}
	}

	return f
}

func (f *Filter) MatchRole(role client.RoleInfo) bool {
	if f == nil || (len(f.verbMap) == 0 && len(f.resourceMap) == 0) {
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
	if len(f.verbMap) == 0 {
		return true
	}

	for _, verb := range ruleVerbs {
		if _, ok := f.verbMap[strings.ToLower(verb)]; ok {
			return true
		}
	}
	return false
}

func (f *Filter) matchResources(ruleResources []string) bool {
	if len(f.resourceMap) == 0 {
		return true
	}

	for _, resource := range ruleResources {
		if _, ok := f.resourceMap[strings.ToLower(resource)]; ok {
			return true
		}
	}
	return false
}

func (f *Filter) MatchBinding(binding client.BindingInfo) bool {
	return true
}

package auditor

import "strings"

type (
	AuditConfigResourceProviders struct {
		Enabled    bool                                     `yaml:"enabled"`
		Rules      []AuditConfigResourceProvider            `yaml:"rules"`
		ScopeRules map[string][]AuditConfigResourceProvider `yaml:"scopeRules"`
	}

	AuditConfigResourceProvider struct {
		Namespace AuditConfigMatcherString `yaml:"namespace"`
	}
)

func (audit *AuditConfigResourceProviders) IsEnabled() bool {
	return audit.Enabled
}

func (audit *AuditConfigResourceProviders) Validate(object ResourceProvider) bool {
	for _, rule := range audit.Rules {
		if rule.IsValid(object) {
			return true
		}
	}

	for scope, rules := range audit.ScopeRules {
		if strings.HasPrefix(object.ResourceID, scope) {
			for _, rule := range rules {
				if rule.IsValid(object) {
					return true
				}
			}
		}
	}

	return false
}

func (ra *AuditConfigResourceProvider) IsValid(resourceProvider ResourceProvider) bool {
	if !ra.Namespace.IsMatching(resourceProvider.Namespace) {
		return false
	}

	return true
}

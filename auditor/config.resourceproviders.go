package auditor

import "strings"

type (
	AuditConfigResourceProviders struct {
		Enabled    bool                                      `yaml:"enabled"`
		Rules      []*AuditConfigResourceProvider            `yaml:"rules"`
		ScopeRules map[string][]*AuditConfigResourceProvider `yaml:"scopeRules"`
	}

	AuditConfigResourceProvider struct {
		AuditConfigBaseRule `yaml:",inline"`
		Namespace           AuditConfigMatcherString `yaml:"namespace,flow"`
	}
)

func (audit *AuditConfigResourceProviders) IsEnabled() bool {
	return audit.Enabled
}

func (audit *AuditConfigResourceProviders) Validate(object AzureResourceProvider) (string, bool) {
	for _, rule := range audit.Rules {
		if rule.IsValid(object) {
			return rule.RuleID, true
		}
	}

	for scope, rules := range audit.ScopeRules {
		if strings.HasPrefix(object.ResourceID, scope) {
			for _, rule := range rules {
				if rule.IsValid(object) {
					return rule.RuleID, true
				}
			}
		}
	}

	return "", false
}

func (rule *AuditConfigResourceProvider) IsValid(object AzureResourceProvider) bool {
	if !rule.Namespace.IsMatching(object.Namespace) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	return rule.handleRuleStatus(object.AzureBaseObject, true)
}

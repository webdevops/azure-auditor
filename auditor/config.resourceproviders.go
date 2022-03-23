package auditor

import (
	"strings"
)

type (
	AuditConfigResourceProviders struct {
		Enabled    bool                                      `yaml:"enabled"`
		Rules      []*AuditConfigResourceProvider            `yaml:"rules"`
		ScopeRules map[string][]*AuditConfigResourceProvider `yaml:"scopeRules"`
	}

	AuditConfigResourceProvider struct {
		AuditConfigBaseRule `yaml:",inline"`
		Namespace           AuditConfigMatcherString `yaml:"namespace,flow"`
		Action              AuditConfigMatcherAction `yaml:"action,flow"`
	}
)

func (audit *AuditConfigResourceProviders) IsEnabled() bool {
	return audit != nil && audit.Enabled
}

func (audit *AuditConfigResourceProviders) Validate(object AzureResourceProvider) (string, bool) {
	for _, rule := range audit.Rules {
		if rule.Action.IsContinue() {
			// rule action is "continue":
			// if rule matches, go to next rule
			// otherwise fail validation here
			if rule.IsRuleMatching(object) {
				continue
			} else {
				return rule.RuleID, false
			}
		}

		// normal rule matching (deny/allow)
		if rule.IsRuleMatching(object) {
			return rule.RuleID, rule.Action.ValidationStatus()
		}
	}

	for scope, rules := range audit.ScopeRules {
		if strings.HasPrefix(object.ResourceID, scope) {
			for _, rule := range rules {
				if rule.Action.IsContinue() {
					// rule action is "continue":
					// if rule matches, go to next rule
					// otherwise fail validation here
					if rule.IsRuleMatching(object) {
						continue
					} else {
						return rule.RuleID, false
					}
				}

				// normal rule matching (deny/allow)
				if rule.IsRuleMatching(object) {
					return rule.RuleID, rule.Action.ValidationStatus()
				}
			}
		}
	}

	return "", false
}

func (rule *AuditConfigResourceProvider) IsRuleMatching(object AzureResourceProvider) bool {
	if !rule.Namespace.IsMatching(object.Namespace) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	return rule.handleRuleStatus(object.AzureBaseObject, true)
}

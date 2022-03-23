package auditor

import (
	"strings"
)

type (
	AuditConfigResourceProviderFeatures struct {
		Enabled    bool                                             `yaml:"enabled"`
		Rules      []*AuditConfigResourceProviderFeature            `yaml:"rules"`
		ScopeRules map[string][]*AuditConfigResourceProviderFeature `yaml:"scopeRules"`
	}

	AuditConfigResourceProviderFeature struct {
		AuditConfigBaseRule `yaml:",inline"`
		Namespace           AuditConfigMatcherString `yaml:"namespace,flow"`
		Feature             AuditConfigMatcherString `yaml:"feature,flow"`
		Action              AuditConfigMatcherAction `yaml:"action,flow"`
	}
)

func (audit *AuditConfigResourceProviderFeatures) IsEnabled() bool {
	return audit != nil && audit.Enabled
}

func (audit *AuditConfigResourceProviderFeatures) Validate(object AzureResourceProviderFeature) (string, bool) {
	for _, rule := range audit.Rules {
		if rule.IsRuleMatching(object) {
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

func (rule *AuditConfigResourceProviderFeature) IsRuleMatching(object AzureResourceProviderFeature) bool {
	if !rule.Namespace.IsMatching(object.Namespace) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.Feature.IsMatching(object.Feature) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	return rule.handleRuleStatus(object.AzureBaseObject, true)
}

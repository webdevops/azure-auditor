package validator

import (
	"strings"
)

type (
	AuditConfigValidation struct {
		Enabled    bool                                    `yaml:"enabled"`
		Metrics    *bool                                   `yaml:"metrics"`
		Name       *string                                 `yaml:"name"`
		Query      *string                                 `yaml:"query"`
		Rules      *[]AuditConfigValidationRule            `yaml:"rules"`
		ScopeRules map[string][]*AuditConfigValidationRule `yaml:"scopeRules"`
	}
)

func (validation *AuditConfigValidation) IsEnabled() bool {
	if validation != nil && validation.Enabled {
		return true
	}

	return false
}

func (validation *AuditConfigValidation) IsMetricsEnabled() bool {
	if validation.Metrics == nil {
		return true
	}

	return *validation.Metrics
}

func (validation *AuditConfigValidation) Validate(object *AzureObject) (string, bool) {
	resourceID := object.ResourceID()

	if validation.Rules != nil {
		for _, rule := range *validation.Rules {
			if rule.IsActionContinue() {
				if rule.IsMatching(object) {
					// valid object, proceed with next rule
					continue
				} else {
					// valid is not valid, returning here
					return rule.Rule, rule.handleRuleStatus(object, false)
				}
			}

			if rule.IsMatching(object) {
				return rule.Rule, rule.handleRuleStatus(object, *rule.ValidationStatus())
			}
		}
	}

	for scopePrefix, rules := range validation.ScopeRules {
		if strings.HasPrefix(resourceID, scopePrefix) {
			for _, rule := range rules {
				if rule.IsActionContinue() {
					if rule.IsMatching(object) {
						// valid object, proceed with next rule
						continue
					} else {
						// valid is not valid, returning here
						return rule.Rule, rule.handleRuleStatus(object, false)
					}
				}

				if rule.IsMatching(object) {
					return rule.Rule, rule.handleRuleStatus(object, *rule.ValidationStatus())
				}
			}
		}
	}

	return "", false
}

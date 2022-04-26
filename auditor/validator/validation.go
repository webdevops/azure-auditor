package validator

import (
	"strings"
)

type (
	AuditConfigValidation struct {
		Enabled    bool                                    `yaml:"enabled"`
		Metrics    *bool                                   `yaml:"metrics"`
		Name       *string                                 `yaml:"name,omitempty"`
		Query      *string                                 `yaml:"query,omitempty"`
		Rules      []*AuditConfigValidationRule            `yaml:"rules,omitempty"`
		ScopeRules map[string][]*AuditConfigValidationRule `yaml:"scopeRules,omitempty"`
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

func (validation *AuditConfigValidation) Reset() {
	if validation.Metrics == nil {
		val := true
		validation.Metrics = &val
	}

	if validation.Rules != nil {
		for _, rule := range validation.Rules {
			rule.Stats.Matches = 0
		}
	}

	for _, rules := range validation.ScopeRules {
		for _, rule := range rules {
			rule.Stats.Matches = 0
		}
	}
}

func (validation *AuditConfigValidation) Validate(object *AzureObject) (string, bool) {
	resourceID := object.ResourceID()

	if validation.Rules != nil {
		for _, rule := range validation.Rules {
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

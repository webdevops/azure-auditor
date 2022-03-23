package auditor

import (
	"fmt"
	"strings"
)

type (
	AuditConfigResourceGroups struct {
		Enabled    bool                                   `yaml:"enabled"`
		Rules      []*AuditConfigResourceGroup            `yaml:"rules"`
		ScopeRules map[string][]*AuditConfigResourceGroup `yaml:"scopeRules"`
	}

	AuditConfigResourceGroup struct {
		AuditConfigBaseRule `yaml:",inline"`
		Name                AuditConfigMatcherString                      `yaml:"name,flow"`
		Location            AuditConfigMatcherString                      `yaml:"location,flow"`
		Tags                map[string]AuditConfigMatcherResourceGroupTag `yaml:"tags"`
		Action              AuditConfigMatcherAction                      `yaml:"action,flow"`
	}

	AuditConfigMatcherResourceGroupTag struct {
		Mode  string                   `yaml:"mode"`
		Value AuditConfigMatcherString `yaml:"value"`
	}
)

func (audit *AuditConfigResourceGroups) IsEnabled() bool {
	return audit != nil && audit.Enabled
}

func (audit *AuditConfigResourceGroups) Validate(object AzureResourceGroup) (string, bool) {
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

func (rule *AuditConfigResourceGroup) IsRuleMatching(object AzureResourceGroup) bool {
	if !rule.Name.IsMatching(object.Name) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.Location.IsMatching(object.Location) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if len(rule.Tags) > 0 {
		for tagName, tagConfig := range rule.Tags {
			tagValue := ""
			if val, exists := object.Tags[tagName]; exists {
				tagValue = strings.TrimSpace(val)
			}

			switch strings.ToLower(tagConfig.Mode) {
			case "", "required":
				if tagValue == "" {
					return rule.handleRuleStatus(object.AzureBaseObject, false)
				}

				fallthrough
			case "optional":
				if tagValue != "" {
					if !tagConfig.Value.IsMatching(tagValue) {
						return rule.handleRuleStatus(object.AzureBaseObject, false)
					}
				}
			default:
				panic(fmt.Sprintf("invalid tag mode \"%s\" found", tagConfig.Mode))
			}
		}
	}

	return rule.handleRuleStatus(object.AzureBaseObject, true)
}

package auditor

import "strings"

type (
	AuditConfigResourceGroups struct {
		Enabled    bool                                   `yaml:"enabled"`
		Rules      []*AuditConfigResourceGroup            `yaml:"rules"`
		ScopeRules map[string][]*AuditConfigResourceGroup `yaml:"scopeRules"`
	}

	AuditConfigResourceGroup struct {
		AuditConfigBaseRule `yaml:",inline"`
		Name                AuditConfigMatcherString            `yaml:"name,flow"`
		Location            AuditConfigMatcherString            `yaml:"location,flow"`
		Tags                map[string]AuditConfigMatcherString `yaml:"tags"`
	}
)

func (audit *AuditConfigResourceGroups) IsEnabled() bool {
	return audit.Enabled
}

func (audit *AuditConfigResourceGroups) Validate(object AzureResourceGroup) (string, bool) {
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

func (rule *AuditConfigResourceGroup) IsValid(object AzureResourceGroup) bool {
	if !rule.Name.IsMatching(object.Name) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.Location.IsMatching(object.Location) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	// if len(ra.Tags) > 0 {
	//	for tagName, tagMatcher := range ra.Tags {
	//		tagValue := ""
	//		if val, exists := resourceGroup.Tags[tagName]; exists {
	//			tagValue = val
	//		}
	//
	//		if !tagMatcher.IsMatching(tagValue) {
	//			return false
	//		}
	//	}
	// }

	return rule.handleRuleStatus(object.AzureBaseObject, true)
}

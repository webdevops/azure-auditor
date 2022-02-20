package auditor

import "strings"

type (
	AuditConfigResourceGroups struct {
		Enabled    bool                                  `yaml:"enabled"`
		Rules      []AuditConfigResourceGroup            `yaml:"rules"`
		ScopeRules map[string][]AuditConfigResourceGroup `yaml:"scopeRules"`
	}

	AuditConfigResourceGroup struct {
		Name     AuditConfigMatcherString            `yaml:"name"`
		Location AuditConfigMatcherString            `yaml:"location"`
		Tags     map[string]AuditConfigMatcherString `yaml:"tags"`
	}
)

func (audit *AuditConfigResourceGroups) IsEnabled() bool {
	return audit.Enabled
}

func (audit *AuditConfigResourceGroups) Validate(object ResourceGroup) bool {
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

func (ra *AuditConfigResourceGroup) IsValid(resourceGroup ResourceGroup) bool {
	if !ra.Name.IsMatching(resourceGroup.Name) {
		return false
	}

	if !ra.Location.IsMatching(resourceGroup.Location) {
		return false
	}

	//if len(ra.Tags) > 0 {
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
	//}

	return true
}

package auditor

import "strings"

type (
	AuditConfigResourceProviderFeatures struct {
		Enabled    bool                                            `yaml:"enabled"`
		Rules      []AuditConfigResourceProviderFeature            `yaml:"rules"`
		ScopeRules map[string][]AuditConfigResourceProviderFeature `yaml:"scopeRules"`
	}

	AuditConfigResourceProviderFeature struct {
		Namespace AuditConfigMatcherString `yaml:"namespace"`
		Feature   AuditConfigMatcherString `yaml:"feature"`
	}
)

func (audit *AuditConfigResourceProviderFeatures) IsEnabled() bool {
	return audit.Enabled
}

func (audit *AuditConfigResourceProviderFeatures) Validate(object ResourceProviderFeature) bool {
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

func (ra *AuditConfigResourceProviderFeature) IsValid(resourceProviderFeature ResourceProviderFeature) bool {
	if !ra.Namespace.IsMatching(resourceProviderFeature.Namespace) {
		return false
	}

	if !ra.Feature.IsMatching(resourceProviderFeature.Feature) {
		return false
	}

	return true
}

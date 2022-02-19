package auditor

type (
	AuditConfigResourceProviderFeatures struct {
		Enabled bool                                 `yaml:"enabled"`
		Rules   []AuditConfigResourceProviderFeature `yaml:"rules"`
	}

	AuditConfigResourceProviderFeature struct {
		Namespace AuditConfigMatcherString `yaml:"namespace"`
		Feature   AuditConfigMatcherString `yaml:"feature"`
	}
)

func (audit *AuditConfigResourceProviderFeatures) IsEnabled() bool {
	return audit.Enabled
}

func (audit *AuditConfigResourceProviderFeatures) Validate(value ResourceProviderFeature) bool {
	for _, rule := range audit.Rules {
		if rule.IsValid(value) {
			return true
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

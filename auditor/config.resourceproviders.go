package auditor

type (
	AuditConfigResourceProviders struct {
		Enabled bool                          `yaml:"enabled"`
		Rules   []AuditConfigResourceProvider `yaml:"rules"`
	}

	AuditConfigResourceProvider struct {
		Namespace AuditConfigMatcherString `yaml:"namespace"`
	}
)

func (audit *AuditConfigResourceProviders) IsEnabled() bool {
	return audit.Enabled
}

func (audit *AuditConfigResourceProviders) Validate(value ResourceProvider) bool {
	for _, rule := range audit.Rules {
		if rule.IsValid(value) {
			return true
		}
	}

	return false
}

func (ra *AuditConfigResourceProvider) IsValid(resourceProvider ResourceProvider) bool {
	if !ra.Namespace.IsMatching(resourceProvider.Namespace) {
		return false
	}

	return true
}

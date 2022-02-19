package auditor

type (
	AuditConfigResourceGroups struct {
		Enabled bool                       `yaml:"enabled"`
		Rules   []AuditConfigResourceGroup `yaml:"rules"`
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

func (audit *AuditConfigResourceGroups) Validate(value ResourceGroup) bool {
	for _, rule := range audit.Rules {
		if rule.IsValid(value) {
			return true
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

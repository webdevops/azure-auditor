package auditor

type (
	AuditConfigKeyvaultAccessPolicies struct {
		Enabled bool                              `yaml:"enabled"`
		Rules   []AuditConfigKeyvaultAccessPolicy `yaml:"rules"`
	}

	AuditConfigKeyvaultAccessPolicy struct {
		Keyvault      AuditConfigMatcherString                   `yaml:"keyvault"`
		ApplicationID AuditConfigMatcherString                   `yaml:"applicationID"`
		ObjectID      AuditConfigMatcherString                   `yaml:"objectID"`
		Permissions   AuditConfigKeyvaultAccessPolicyPermissions `yaml:"permissions"`
	}

	AuditConfigKeyvaultAccessPolicyPermissions struct {
		Certificates AuditConfigMatcherList `yaml:"certificates"`
		Secrets      AuditConfigMatcherList `yaml:"secrets"`
		Keys         AuditConfigMatcherList `yaml:"keys"`
		Storage      AuditConfigMatcherList `yaml:"storage"`
	}
)

func (audit *AuditConfigKeyvaultAccessPolicies) IsEnabled() bool {
	return audit.Enabled
}

func (audit *AuditConfigKeyvaultAccessPolicies) Validate(value KeyvaultAccessPolicy) bool {
	for _, rule := range audit.Rules {
		if rule.IsValid(value) {
			return true
		}
	}

	return false
}

func (ra *AuditConfigKeyvaultAccessPolicy) IsValid(keyvaultAccessPolicy KeyvaultAccessPolicy) bool {
	if !ra.Keyvault.IsMatching(keyvaultAccessPolicy.Keyvault) {
		return false
	}

	if !ra.ApplicationID.IsMatching(keyvaultAccessPolicy.ApplicationID) {
		return false
	}

	if !ra.ObjectID.IsMatching(keyvaultAccessPolicy.ObjectID) {
		return false
	}

	if !ra.Permissions.Certificates.IsMatching(keyvaultAccessPolicy.Permissions.Certificates) {
		return false
	}

	if !ra.Permissions.Secrets.IsMatching(keyvaultAccessPolicy.Permissions.Secrets) {
		return false
	}

	if !ra.Permissions.Keys.IsMatching(keyvaultAccessPolicy.Permissions.Keys) {
		return false
	}

	if !ra.Permissions.Storage.IsMatching(keyvaultAccessPolicy.Permissions.Storage) {
		return false
	}

	return true
}

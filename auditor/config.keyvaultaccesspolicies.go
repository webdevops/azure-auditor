package auditor

import "strings"

type (
	AuditConfigKeyvaultAccessPolicies struct {
		Enabled    bool                                          `yaml:"enabled"`
		Rules      []*AuditConfigKeyvaultAccessPolicy            `yaml:"rules"`
		ScopeRules map[string][]*AuditConfigKeyvaultAccessPolicy `yaml:"scopeRules"`
	}

	AuditConfigKeyvaultAccessPolicy struct {
		AuditConfigBaseRule `yaml:",inline"`
		Keyvault            AuditConfigMatcherString                   `yaml:"keyvault,flow"`
		ApplicationID       AuditConfigMatcherString                   `yaml:"applicationID,flow"`
		ObjectID            AuditConfigMatcherString                   `yaml:"objectID,flow"`
		Permissions         AuditConfigKeyvaultAccessPolicyPermissions `yaml:"permissions"`
	}

	AuditConfigKeyvaultAccessPolicyPermissions struct {
		Certificates AuditConfigMatcherList `yaml:"certificates,flow"`
		Secrets      AuditConfigMatcherList `yaml:"secrets,flow"`
		Keys         AuditConfigMatcherList `yaml:"keys,flow"`
		Storage      AuditConfigMatcherList `yaml:"storage,flow"`
	}
)

func (audit *AuditConfigKeyvaultAccessPolicies) IsEnabled() bool {
	return audit.Enabled
}

func (audit *AuditConfigKeyvaultAccessPolicies) Validate(object AzureKeyvaultAccessPolicy) (string, bool) {
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

func (rule *AuditConfigKeyvaultAccessPolicy) IsValid(object AzureKeyvaultAccessPolicy) bool {
	if !rule.Keyvault.IsMatching(object.Keyvault) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.ApplicationID.IsMatching(object.ApplicationID) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.ObjectID.IsMatching(object.ObjectID) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.Permissions.Certificates.IsMatching(object.Permissions.Certificates) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.Permissions.Secrets.IsMatching(object.Permissions.Secrets) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.Permissions.Keys.IsMatching(object.Permissions.Keys) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.Permissions.Storage.IsMatching(object.Permissions.Storage) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	return rule.handleRuleStatus(object.AzureBaseObject, true)
}

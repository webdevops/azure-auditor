package auditor

import "strings"

type (
	AuditConfigKeyvaultAccessPolicies struct {
		Enabled    bool                                          `yaml:"enabled"`
		Rules      []*AuditConfigKeyvaultAccessPolicy            `yaml:"rules"`
		ScopeRules map[string][]*AuditConfigKeyvaultAccessPolicy `yaml:"scopeRules"`
	}

	AuditConfigKeyvaultAccessPolicy struct {
		AuditConfigBaseRule    `yaml:",inline"`
		Keyvault               AuditConfigMatcherString                   `yaml:"keyvault,flow"`
		PrincipalType          AuditConfigMatcherString                   `yaml:"principalType,flow"`
		PrincipalDisplayName   AuditConfigMatcherString                   `yaml:"principalDisplayName,flow"`
		PrincipalApplicationID AuditConfigMatcherString                   `yaml:"principalApplicationID,flow"`
		PrincipalObjectID      AuditConfigMatcherString                   `yaml:"principalObjectID,flow"`
		Permissions            AuditConfigKeyvaultAccessPolicyPermissions `yaml:"permissions"`
		Action                 AuditConfigMatcherAction                   `yaml:"action,flow"`
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
			return rule.RuleID, rule.Action.ValidationStatus()
		}
	}

	for scope, rules := range audit.ScopeRules {
		if strings.HasPrefix(object.ResourceID, scope) {
			for _, rule := range rules {
				if rule.IsValid(object) {
					return rule.RuleID, rule.Action.ValidationStatus()
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

	if !rule.PrincipalType.IsMatching(object.PrincipalType) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.PrincipalDisplayName.IsMatching(object.PrincipalDisplayName) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.PrincipalApplicationID.IsMatching(object.PrincipalApplicationID) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.PrincipalObjectID.IsMatching(object.PrincipalObjectID) {
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

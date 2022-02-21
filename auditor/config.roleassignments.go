package auditor

import "strings"

type (
	AuditConfigRoleAssignments struct {
		Enabled    bool                                    `yaml:"enabled"`
		Rules      []*AuditConfigRoleAssignment            `yaml:"rules"`
		ScopeRules map[string][]*AuditConfigRoleAssignment `yaml:"scopeRules"`
	}

	AuditConfigRoleAssignment struct {
		AuditConfigBaseRule `yaml:",inline"`
		Type                AuditConfigMatcherString `yaml:"type,flow"`
		Scope               AuditConfigMatcherString `yaml:"scope,flow"`

		PrincipalID   AuditConfigMatcherString `yaml:"principalID,flow"`
		PrincipalType AuditConfigMatcherString `yaml:"principalType,flow"`
		PrincipalName AuditConfigMatcherString `yaml:"prinicpalName,flow"`

		RoleDefinitionID   AuditConfigMatcherString `yaml:"roleDefinitionID,flow"`
		RoleDefinitionName AuditConfigMatcherString `yaml:"roleDefinitionName,flow"`

		Description AuditConfigMatcherString `yaml:"description,flow"`
	}
)

func (audit *AuditConfigRoleAssignments) IsEnabled() bool {
	return audit.Enabled
}

func (audit *AuditConfigRoleAssignments) Validate(object AzureRoleAssignment) bool {
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

func (rule *AuditConfigRoleAssignment) IsValid(object AzureRoleAssignment) bool {
	if !rule.Type.IsMatching(object.Type) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.Scope.IsMatching(object.Scope) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.PrincipalID.IsMatching(object.PrincipalID) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.PrincipalType.IsMatching(object.PrincipalType) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.PrincipalName.IsMatching(object.PrincipalName) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.RoleDefinitionID.IsMatching(object.RoleDefinitionID) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.RoleDefinitionName.IsMatching(object.RoleDefinitionName) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.Description.IsMatching(object.Description) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	return rule.handleRuleStatus(object.AzureBaseObject, true)
}

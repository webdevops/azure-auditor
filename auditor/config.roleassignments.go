package auditor

import "strings"

type (
	AuditConfigRoleAssignments struct {
		Enabled    bool                                   `yaml:"enabled"`
		Rules      []AuditConfigRoleAssignment            `yaml:"rules"`
		ScopeRules map[string][]AuditConfigRoleAssignment `yaml:"scopeRules"`
	}

	AuditConfigRoleAssignment struct {
		Type  AuditConfigMatcherString `yaml:"type"`
		Scope AuditConfigMatcherString `yaml:"scope"`

		PrincipalID   AuditConfigMatcherString `yaml:"principalID"`
		PrincipalType AuditConfigMatcherString `yaml:"principalType"`
		PrincipalName AuditConfigMatcherString `yaml:"prinicpalName"`

		RoleDefinitionID   AuditConfigMatcherString `yaml:"roleDefinitionID"`
		RoleDefinitionName AuditConfigMatcherString `yaml:"roleDefinitionName"`

		Description AuditConfigMatcherString `yaml:"description"`
	}
)

func (audit *AuditConfigRoleAssignments) IsEnabled() bool {
	return audit.Enabled
}

func (audit *AuditConfigRoleAssignments) Validate(object RoleAssignment) bool {
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

func (ra *AuditConfigRoleAssignment) IsValid(roleAssignment RoleAssignment) bool {
	if !ra.Type.IsMatching(roleAssignment.Type) {
		return false
	}

	if !ra.Scope.IsMatching(roleAssignment.Scope) {
		return false
	}

	if !ra.PrincipalID.IsMatching(roleAssignment.PrincipalID) {
		return false
	}

	if !ra.PrincipalType.IsMatching(roleAssignment.PrincipalType) {
		return false
	}

	if !ra.PrincipalName.IsMatching(roleAssignment.PrincipalName) {
		return false
	}

	if !ra.RoleDefinitionID.IsMatching(roleAssignment.RoleDefinitionID) {
		return false
	}

	if !ra.RoleDefinitionName.IsMatching(roleAssignment.RoleDefinitionName) {
		return false
	}

	if !ra.Description.IsMatching(roleAssignment.Description) {
		return false
	}

	return true
}

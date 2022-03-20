package auditor

import (
	"strings"
	"time"
)

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

		PrincipalObjectID      AuditConfigMatcherString `yaml:"principalObjectID,flow"`
		PrincipalApplicationID AuditConfigMatcherString `yaml:"principalApplicationID,flow"`
		PrincipalType          AuditConfigMatcherString `yaml:"principalType,flow"`
		PrincipalDisplayName   AuditConfigMatcherString `yaml:"principalDisplayName,flow"`

		RoleDefinitionID   AuditConfigMatcherString `yaml:"roleDefinitionID,flow"`
		RoleDefinitionName AuditConfigMatcherString `yaml:"roleDefinitionName,flow"`

		Description AuditConfigMatcherString `yaml:"description,flow"`

		Age *time.Duration `yaml:"age,flow"`
	}
)

func (audit *AuditConfigRoleAssignments) IsEnabled() bool {
	return audit.Enabled
}

func (audit *AuditConfigRoleAssignments) Validate(object AzureRoleAssignment) (string, bool) {
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

func (rule *AuditConfigRoleAssignment) IsValid(object AzureRoleAssignment) bool {
	if !rule.Type.IsMatching(object.Type) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.Scope.IsMatching(object.Scope) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.PrincipalObjectID.IsMatching(object.PrincipalObjectID) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.PrincipalApplicationID.IsMatching(object.PrincipalApplicationID) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.PrincipalType.IsMatching(object.PrincipalType) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.PrincipalDisplayName.IsMatching(object.PrincipalDisplayName) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.RoleDefinitionID.IsMatching(object.RoleDefinitionID) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if !rule.RoleDefinitionName.IsMatching(object.RoleDefinitionName) {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	if rule.Age != nil && rule.Age.Seconds() <= object.Age.Seconds() {
		return rule.handleRuleStatus(object.AzureBaseObject, false)
	}

	return rule.handleRuleStatus(object.AzureBaseObject, true)
}

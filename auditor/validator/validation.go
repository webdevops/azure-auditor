package validator

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/webdevops/azure-auditor/auditor/types"
)

type (
	AuditConfigValidation struct {
		Enabled              bool                                    `json:"enabled"`
		Metrics              *bool                                   `json:"metrics"`
		Query                *string                                 `json:"query,omitempty"`
		Timespan             *string                                 `json:"timespan,omitempty"`
		Workspaces           *[]string                               `json:"workspaces,omitempty"`
		AdditionalWorkspaces *[]string                               `json:"additionalWorkspaces,omitempty"`
		Rules                []*AuditConfigValidationRule            `json:"rules,omitempty"`
		Prometheus           AuditConfigValidationPrometheus         `json:"prometheus,omitempty"`
		Report               AuditConfigValidationReport             `json:"report,omitempty"`
		Mapping              *map[string]string                      `json:"mapping,omitempty"`
		Enrich               bool                                    `json:"enrich,omitempty"`
		ScopeRules           map[string][]*AuditConfigValidationRule `json:"scopeRules,omitempty"`
	}

	AuditConfigValidationPrometheus struct {
		Labels map[string]string `json:"labels,omitempty"`
	}

	AuditConfigValidationReport struct {
		Filter struct {
			Status   string `json:"status,omitempty"`
			Resource string `json:"resource,omitempty"`
			Rule     string `json:"rule,omitempty"`
		} `json:"filter,omitempty"`

		Settings struct {
			GroupBy string `json:"groupBy,omitempty"`
			Fields  string `json:"fields,omitempty"`
		} `json:"settings,omitempty"`
	}
)

func (validation *AuditConfigValidation) IsEnabled() bool {
	if validation != nil && validation.Enabled {
		return true
	}

	return false
}

func (validation *AuditConfigValidation) IsMetricsEnabled() bool {
	if validation.Metrics == nil {
		return true
	}

	return *validation.Metrics
}

func (validation *AuditConfigValidation) Reset() {
	if validation.Metrics == nil {
		val := true
		validation.Metrics = &val
	}

	if validation.Rules != nil {
		for _, rule := range validation.Rules {
			rule.Stats.Matches = 0
		}
	}

	for _, rules := range validation.ScopeRules {
		for _, rule := range rules {
			rule.Stats.Matches = 0
		}
	}
}

func (validation *AuditConfigValidation) PrometheusLabels() []string {
	labels := []string{}

	for name := range validation.Prometheus.Labels {
		labels = append(labels, name)
	}

	return labels
}

func (validation *AuditConfigValidation) CreatePrometheusMetricFromAzureObject(obj *AzureObject, ruleId string) prometheus.Labels {
	labels := prometheus.Labels{
		"rule": ruleId,
	}

	for labelName, fieldName := range validation.Prometheus.Labels {
		labels[labelName] = obj.ToPrometheusLabel(fieldName)
	}

	return labels
}

func (validation *AuditConfigValidation) Validate(object *AzureObject) (string, types.RuleStatus) {
	resourceID := object.ResourceID()

	if validation.Rules != nil {
		for _, rule := range validation.Rules {
			if rule.IsActionContinue() {
				if rule.IsMatching(object) {
					// valid object, proceed with next rule
					continue
				} else {
					// valid is not valid, returning here
					return rule.Rule, rule.handleRuleStatus(object, types.RuleStatusDeny)
				}
			}

			if rule.IsMatching(object) {
				return rule.Rule, rule.handleRuleStatus(object, *rule.ValidationStatus())
			}
		}
	}

	for scopePrefix, rules := range validation.ScopeRules {
		if strings.HasPrefix(resourceID, scopePrefix) {
			for _, rule := range rules {
				if rule.IsActionContinue() {
					if rule.IsMatching(object) {
						// valid object, proceed with next rule
						continue
					} else {
						// valid is not valid, returning here
						return rule.Rule, rule.handleRuleStatus(object, types.RuleStatusDeny)
					}
				}

				if rule.IsMatching(object) {
					return rule.Rule, rule.handleRuleStatus(object, *rule.ValidationStatus())
				}
			}
		}
	}

	return "__DEFAULTDENY__", types.RuleStatusDeny
}

package validator

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

type (
	AuditConfigValidation struct {
		Enabled              bool                                    `yaml:"enabled"`
		Metrics              *bool                                   `yaml:"metrics"`
		Query                *string                                 `yaml:"query,omitempty"`
		Timespan             *string                                 `yaml:"timespan,omitempty"`
		Workspaces           *[]string                               `yaml:"workspaces,omitempty"`
		AdditionalWorkspaces *[]string                               `yaml:"additionalWorkspaces,omitempty"`
		Rules                []*AuditConfigValidationRule            `yaml:"rules,omitempty"`
		Prometheus           AuditConfigValidationPrometheus         `yaml:"prometheus,omitempty"`
		Report               AuditConfigValidationReport             `yaml:"report,omitempty"`
		Mapping              *map[string]string                      `yaml:"mapping,omitempty"`
		Enrich               bool                                    `yaml:"enrich,omitempty"`
		ScopeRules           map[string][]*AuditConfigValidationRule `yaml:"scopeRules,omitempty"`
	}

	AuditConfigValidationPrometheus struct {
		Labels map[string]string `yaml:"labels,omitempty"`
	}

	AuditConfigValidationReport struct {
		Filter struct {
			Status   string `yaml:"status,omitempty"`
			Resource string `yaml:"resource,omitempty"`
			Rule     string `yaml:"rule,omitempty"`
		} `yaml:"filter,omitempty"`

		Settings struct {
			GroupBy string `yaml:"groupBy,omitempty"`
			Fields  string `yaml:"fields,omitempty"`
		} `yaml:"settings,omitempty"`
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

func (validation *AuditConfigValidation) Validate(object *AzureObject) (string, bool) {
	resourceID := object.ResourceID()

	if validation.Rules != nil {
		for _, rule := range validation.Rules {
			if rule.IsActionContinue() {
				if rule.IsMatching(object) {
					// valid object, proceed with next rule
					continue
				} else {
					// valid is not valid, returning here
					return rule.Rule, rule.handleRuleStatus(object, false)
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
						return rule.Rule, rule.handleRuleStatus(object, false)
					}
				}

				if rule.IsMatching(object) {
					return rule.Rule, rule.handleRuleStatus(object, *rule.ValidationStatus())
				}
			}
		}
	}

	return "", false
}

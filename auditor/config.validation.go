package auditor

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/gofrs/uuid"
	log "github.com/sirupsen/logrus"
)

type (
	AuditConfigValidation struct {
		Enabled    bool                                    `yaml:"enabled"`
		Rules      *[]AuditConfigValidationRule            `yaml:"rules"`
		ScopeRules map[string][]*AuditConfigValidationRule `yaml:"scopeRules"`
	}

	AuditConfigValidationRule struct {
		Rule   string `yaml:"rule"`
		Fields map[string]AuditConfigValidationRuleField
		Action string `yaml:"action"`
	}

	AuditConfigValidationRuleField struct {
		Required bool           `yaml:"required,omitempty"`
		Match    *string        `yaml:"match,omitempty"`
		AllOf    *[]string      `yaml:"allOf,omitempty,flow"`
		AnyOf    *[]string      `yaml:"anyOf,omitempty,flow"`
		Regexp   *string        `yaml:"regexp,omitempty"`
		regexp   *regexp.Regexp `yaml:"-"`

		Min *float64 `yaml:"min,omitempty"`
		Max *float64 `yaml:"max,omitempty"`

		MinDuration *time.Duration `yaml:"minDuration,omitempty"`
		MaxDuration *time.Duration `yaml:"maxDuration,omitempty"`
	}
)

func (validation *AuditConfigValidation) IsEnabled() bool {
	if validation != nil && validation.Enabled {
		return true
	}

	return false
}

func (validation *AuditConfigValidation) Validate(object *AzureObject) (string, bool) {
	resourceID := object.ResourceID()

	if validation.Rules != nil {
		for _, rule := range *validation.Rules {
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

func (matcher *AuditConfigValidationRule) UnmarshalYAML(unmarshal func(interface{}) error) error {
	config := map[string]interface{}{}
	err := unmarshal(&config)
	if err == nil {
		matcher.Fields = map[string]AuditConfigValidationRuleField{}
		matcher.Action = "allow"

		for name, val := range config {
			switch name {
			case "rule":
				matcher.Rule = interfaceToString(val)
			case "action":
				matcher.Action = interfaceToString(val)
			default:
				switch v := val.(type) {
				case string:
					matcher.Fields[name] = AuditConfigValidationRuleField{
						Required: true,
						Match:    &v,
					}
				case []string:
					matcher.Fields[name] = AuditConfigValidationRuleField{
						Required: true,
						AllOf:    &v,
					}
				case []interface{}:
					list := []string{}
					for _, val := range v {
						if v, ok := val.(string); ok {
							list = append(list, v)
						}
					}
					matcher.Fields[name] = AuditConfigValidationRuleField{
						Required: true,
						AllOf:    &list,
					}
				case map[string]interface{}:
					ruleField := AuditConfigValidationRuleField{
						Required: true,
					}
					if x, ok := v["required"].(bool); ok {
						ruleField.Required = x
					}

					if x, ok := v["match"].(string); ok {
						ruleField.Match = &x
					}

					if x, ok := v["allOf"].([]string); ok {
						ruleField.AllOf = &x
					}

					if x, ok := v["anyOf"].([]string); ok {
						ruleField.AnyOf = &x
					}

					if x, ok := v["regexp"].(string); ok {
						ruleField.Regexp = &x
						ruleField.regexp = regexp.MustCompile(x)
					}

					if x, ok := v["min"].(float64); ok {
						ruleField.Min = &x
					}

					if x, ok := v["max"].(float64); ok {
						ruleField.Max = &x
					}

					if x, ok := v["minDuration"].(string); ok {
						if dur, err := time.ParseDuration(x); err == nil {
							ruleField.MinDuration = &dur
						} else {
							panic(fmt.Sprintf("unable to parse minDuration value \"%v\"", x))
						}
					}
					if x, ok := v["maxDuration"].(string); ok {
						if dur, err := time.ParseDuration(x); err == nil {
							ruleField.MaxDuration = &dur
						} else {
							panic(fmt.Sprintf("unable to parse maxDuration value \"%v\"", x))
						}
					}

					matcher.Fields[name] = ruleField
				default:
					fmt.Println(name)
					panic(v)
				}
			}
		}
	} else {
		return errors.New("invalid rule map")
	}

	matcher.Action = strings.ToLower(matcher.Action)

	if matcher.Rule == "" {
		ruleId, _ := uuid.DefaultGenerator.NewV4()
		matcher.Rule = fmt.Sprintf("<rule:%s>", ruleId)
	}

	return nil
}

func (rule *AuditConfigValidationRule) handleRuleStatus(object *AzureObject, status bool) bool {
	log.WithFields(log.Fields{
		"resourceID":       object.ResourceID(),
		"rule":             rule.Rule,
		"validationStatus": status,
	}).Debugf("validation status: \"%v\"", status)
	return status
}

func (matcher *AuditConfigValidationRule) IsActionContinue() bool {
	return matcher.Action == "continue"
}

func (matcher *AuditConfigValidationRule) ValidationStatus() *bool {
	switch strings.ToLower(matcher.Action) {
	case "deny":
		return to.BoolPtr(false)
	case "allow":
		return to.BoolPtr(true)
	case "continue":
		return nil
	}
	return nil
}

func (matcher *AuditConfigValidationRule) IsMatching(object *AzureObject) bool {
	for fieldName, fieldValidator := range matcher.Fields {
		if v, exists := (*object)[fieldName]; exists {
			switch fieldValue := v.(type) {
			case string:
				if fieldValidator.Required && fieldValue == "" {
					// required, but empty
					return false
				}

				if fieldValue == "" {
					// optional, but empty
					continue
				}

				if fieldValidator.regexp != nil {
					// validate with regexp
					if !fieldValidator.regexp.MatchString(fieldValue) {
						return false
					}
				} else if fieldValidator.Match != nil {
					// validate with direct matching
					if !strings.EqualFold(*fieldValidator.Match, fieldValue) {
						return false
					}
				}
			case []string:
				if fieldValidator.Required && len(fieldValue) == 0 {
					// required, but empty
					return false
				}

				if len(fieldValue) == 0 {
					// optional, but empty
					continue
				}

				if fieldValidator.regexp != nil {
					// validate with regexp
					for _, fieldValueItem := range fieldValue {
						if !fieldValidator.regexp.MatchString(fieldValueItem) {
							return false
						}
					}
				} else if fieldValidator.Match != nil {
					// validate with direct matching
					for _, fieldValueItem := range fieldValue {
						if !strings.EqualFold(*fieldValidator.Match, fieldValueItem) {
							return false
						}
					}
				} else if fieldValidator.AllOf != nil && len(*fieldValidator.AllOf) > 0 {
					return stringListIsMatchingAllOf(fieldValue, *fieldValidator.AllOf)
				} else if fieldValidator.AnyOf != nil && len(*fieldValidator.AnyOf) > 0 {
					return stringListIsMatchingAnyOf(fieldValue, *fieldValidator.AnyOf)
				}

			case time.Duration:
				if fieldValidator.MinDuration != nil && fieldValue.Seconds() < fieldValidator.MinDuration.Seconds() {
					return false
				}

				if fieldValidator.MaxDuration != nil && fieldValue.Seconds() > fieldValidator.MaxDuration.Seconds() {
					return false
				}
			default:
				return false
			}
		} else {
			if fieldValidator.Required {
				// required, but empty
				return false
			}
		}
	}
	return true
}

func stringListIsMatchingAllOf(list, matcherList []string) bool {
	matchCount := int(0)
	for _, match := range matcherList {
		for _, val := range list {
			if strings.EqualFold(val, match) {
				matchCount++
			}
		}
	}
	return matchCount == len(list)
}

func stringListIsMatchingAnyOf(list, matcherList []string) bool {
	for _, match := range matcherList {
		for _, val := range list {
			if !strings.EqualFold(val, match) {
				return false
			}
		}
	}

	return true
}

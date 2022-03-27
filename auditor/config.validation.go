package auditor

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/gofrs/uuid"
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
		Match    string         `yaml:"match,omitempty"`
		List     []string       `yaml:"list,omitempty,flow"`
		Regexp   string         `yaml:"regexp,omitempty"`
		regexp   *regexp.Regexp `yaml:"-"`
	}
)

func (conf *AuditConfigValidation) IsEnabled() bool {
	if conf != nil && conf.Enabled {
		return true
	}

	return false
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
						Match:    v,
					}
				case []string:
					matcher.Fields[name] = AuditConfigValidationRuleField{
						Required: true,
						List:     v,
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
						List:     list,
					}
				case map[string]interface{}:
					ruleField := AuditConfigValidationRuleField{
						Required: true,
					}
					if x, ok := v["required"].(bool); ok {
						ruleField.Required = x
					}

					if x, ok := v["match"].(string); ok {
						ruleField.Match = x
					}

					if x, ok := v["list"].([]string); ok {
						ruleField.List = x
					}

					if x, ok := v["regexp"].(string); ok {
						ruleField.Regexp = x
						ruleField.regexp = regexp.MustCompile(x)
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

func (matcher *AuditConfigValidation) Validate(object *AzureObject) (string, bool) {
	resourceID := object.ResourceID()

	if matcher.Rules != nil {
		for _, rule := range *matcher.Rules {
			if rule.IsActionContinue() {
				if rule.IsMatching(object) {
					// valid object, proceed with next rule
					continue
				} else {
					// valid is not valid, returning here
					return rule.Rule, false
				}
			}

			if rule.IsMatching(object) {
				return rule.Rule, *rule.ValidationStatus()
			}
		}
	}

	for scopePrefix, rules := range matcher.ScopeRules {
		if strings.HasPrefix(resourceID, scopePrefix) {
			for _, rule := range rules {
				if rule.IsActionContinue() {
					if rule.IsMatching(object) {
						// valid object, proceed with next rule
						continue
					} else {
						// valid is not valid, returning here
						return rule.Rule, false
					}
				}

				if rule.IsMatching(object) {
					return rule.Rule, *rule.ValidationStatus()
				}
			}
		}
	}

	return "", false
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
		var fieldValue *string

		if val, ok := (*object)[fieldName].(string); ok && val != "" {
			fieldValue = &val
		}

		if fieldValidator.Required && fieldValue == nil {
			// required, but empty
			return false
		}

		if fieldValue == nil {
			// optional, but empty
			continue
		}

		if fieldValidator.regexp != nil {
			// validate with regexp
			if !fieldValidator.regexp.MatchString(*fieldValue) {
				return false
			}
		} else if fieldValidator.Match != "" {
			// validate with direct matching
			if !strings.EqualFold(fieldValidator.Match, *fieldValue) {
				return false
			}
		}
	}
	return true
}

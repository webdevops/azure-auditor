package validator

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
		// general
		Not      bool `yaml:"bool,omitempty"`
		Required bool `yaml:"required,omitempty"`

		// CAST
		ParseAs *string `yaml:"castTo,omitempty"`

		// STRING type
		Match  *string        `yaml:"match,omitempty"`
		Regexp *string        `yaml:"regexp,omitempty"`
		regexp *regexp.Regexp `yaml:"-"`

		// STRINGLIST type
		AllOf *[]string `yaml:"allOf,omitempty,flow"`
		AnyOf *[]string `yaml:"anyOf,omitempty,flow"`

		// NUMERIC
		Min *float64 `yaml:"min,omitempty"`
		Max *float64 `yaml:"max,omitempty"`

		// DURATION
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
					// normalize map
					tmp := map[string]interface{}{}
					for tmpName, tmpValue := range v {
						tmpName = strings.ToLower(tmpName)
						tmp[tmpName] = tmpValue
					}
					v = tmp

					ruleField := AuditConfigValidationRuleField{
						Required: true,
					}

					if x, ok := v["not"].(bool); ok {
						ruleField.Not = x
					}

					if x, ok := v["required"].(bool); ok {
						ruleField.Required = x
					}
					if x, ok := v["parseas"].(string); ok {
						switch x {
						case "duration":
							ruleField.ParseAs = to.StringPtr("duration")
						case "timesince":
							ruleField.ParseAs = to.StringPtr("timesince")
						default:
							panic(fmt.Sprintf("parseAs value \"%v\" is not allowed", x))
						}
					}

					if x, ok := v["match"].(string); ok {
						ruleField.Match = &x
					}

					if x, ok := v["allof"].([]interface{}); ok {
						x := interfaceListToStringList(x)
						ruleField.AllOf = &x
					}

					if x, ok := v["anyof"].([]interface{}); ok {
						x := interfaceListToStringList(x)
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

					if x, ok := v["minduration"].(string); ok {
						if dur, err := time.ParseDuration(x); err == nil {
							ruleField.MinDuration = &dur
						} else {
							panic(fmt.Sprintf("unable to parse minDuration value \"%v\"", x))
						}
					}
					if x, ok := v["maxduration"].(string); ok {
						if dur, err := time.ParseDuration(x); err == nil {
							ruleField.MaxDuration = &dur
						} else {
							panic(fmt.Sprintf("unable to parse maxDuration value \"%v\"", x))
						}
					}

					matcher.Fields[name] = ruleField
				default:
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
	for fieldName, field := range matcher.Fields {
		if v, exists := (*object)[fieldName]; exists {
			status, skipField := field.IsMatching(v)

			// check if field is a continue field (eg. status cannot be applied)
			if skipField {
				continue
			}

			// check if status should be inverted (not)
			if field.Not {
				if status {
					return false
				} else {
					continue
				}
			}

			// field is not matching, object is not matching
			if !status {
				return false
			}
		} else {
			if field.Required {
				// required, but empty -> field is not matching, object is not matching
				return false
			}
		}
	}

	// if all fields are matching, object is matching
	return true
}

func (field *AuditConfigValidationRuleField) IsMatching(v interface{}) (bool, bool) {
	switch fieldValue := v.(type) {
	// STRING type
	case string:
		if field.Required && fieldValue == "" {
			// required, but empty
			return false, false
		}

		if fieldValue == "" {
			// optional, but empty
			return false, true
		}

		if field.ParseAs != nil {
			switch *field.ParseAs {
			case "duration":
				if dur, err := time.ParseDuration(fieldValue); err == nil {
					return field.IsMatching(dur)
				} else {
					// parse failed, not matching
					return false, false
				}
			case "timesince":
				if fieldTime := parseTime(fieldValue); fieldTime != nil {
					return field.IsMatching(time.Since(*fieldTime))
				} else {
					// parse failed, not matching
					return false, false
				}
			}
		}

		if field.regexp != nil {
			// validate with regexp
			if !field.regexp.MatchString(fieldValue) {
				return false, false
			}
		} else if field.Match != nil {
			// validate with direct matching
			if !strings.EqualFold(*field.Match, fieldValue) {
				return false, false
			}
		}
	// STRING LIST type
	case []string:
		if field.Required && len(fieldValue) == 0 {
			// required, but empty
			return false, false
		}

		if len(fieldValue) == 0 {
			// optional, but empty
			return false, true
		}

		if field.regexp != nil {
			// validate with regexp
			for _, fieldValueItem := range fieldValue {
				if !field.regexp.MatchString(fieldValueItem) {
					return false, false
				}
			}
		} else if field.Match != nil {
			// validate with direct matching
			for _, fieldValueItem := range fieldValue {
				if !strings.EqualFold(*field.Match, fieldValueItem) {
					return false, false
				}
			}
		} else if field.AllOf != nil && len(*field.AllOf) > 0 {
			return stringListIsMatchingAllOf(fieldValue, *field.AllOf), false
		} else if field.AnyOf != nil && len(*field.AnyOf) > 0 {
			return stringListIsMatchingAnyOf(fieldValue, *field.AnyOf), false
		}

	// DURATION type
	case time.Duration:
		if field.MinDuration != nil && fieldValue.Seconds() < field.MinDuration.Seconds() {
			return false, false
		}

		if field.MaxDuration != nil && fieldValue.Seconds() > field.MaxDuration.Seconds() {
			return false, false
		}

	// UNKNOWN type
	default:
		return false, false
	}

	return true, false
}

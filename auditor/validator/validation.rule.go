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
	AuditConfigValidationRule struct {
		Rule   string `yaml:"rule"`
		Fields map[string]AuditConfigValidationRuleField
		Action string `yaml:"action"`
	}
)

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

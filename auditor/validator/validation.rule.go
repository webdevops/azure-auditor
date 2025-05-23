package validator

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofrs/uuid"
	"github.com/robertkrimen/otto"
	_ "github.com/robertkrimen/otto/underscore"
	"github.com/webdevops/go-common/utils/to"
	"go.uber.org/zap"

	"github.com/webdevops/azure-auditor/auditor/types"
)

type (
	AuditConfigValidationRule struct {
		Rule   string `json:"rule"`
		Fields map[string]AuditConfigValidationRuleField
		Action string `json:"action"`

		// FUNC
		CustomFunction *string `json:"func,omitempty"`
		customFunction *otto.Script

		Stats AuditConfigValidationRuleStats `json:"stats"`
	}

	AuditConfigValidationRuleStats struct {
		Matches int64 `json:"matches"`
	}
)

var (
	vm     = otto.New()
	vmLock = sync.Mutex{}
	Logger *zap.SugaredLogger
)

func (matcher *AuditConfigValidationRule) UnmarshalJSON(b []byte) error {
	config := map[string]interface{}{}
	err := json.Unmarshal(b, &config)
	if err == nil {
		matcher.Fields = map[string]AuditConfigValidationRuleField{}
		matcher.Action = "allow"

		for name, val := range config {
			switch name {
			case "rule":
				matcher.Rule = interfaceToString(val)
			case "action":
				matcher.Action = interfaceToString(val)
			case "func":
				funcString := interfaceToString(val)
				matcher.CustomFunction = &funcString
				if funcCall, err := vm.Compile("", funcString); err == nil {
					matcher.customFunction = funcCall
				} else {
					return fmt.Errorf("unable to parse func: %w\n\n%v", err, funcString)
				}
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
		matcher.Rule = fmt.Sprintf("rule:%s", ruleId)
	}

	matcher.Stats = AuditConfigValidationRuleStats{Matches: 0}

	return nil
}

func (rule *AuditConfigValidationRule) handleRuleStatus(object *AzureObject, status types.RuleStatus) types.RuleStatus {
	atomic.AddInt64(&rule.Stats.Matches, 1)
	if Logger != nil {
		Logger.With(
			zap.String("resourceID", object.ResourceID()),
			zap.String("rule", rule.Rule),
			zap.String("validationStatus", status.String()),
		).Debugf("validation status: \"%v\"", status)
	}
	return status
}

func (matcher *AuditConfigValidationRule) IsActionContinue() bool {
	return matcher.Action == "continue"
}

func (matcher *AuditConfigValidationRule) ValidationStatus() (ret *types.RuleStatus) {
	switch strings.ToLower(matcher.Action) {
	case "ignore":
		ret = &types.RuleStatusIgnore
	case "deny":
		ret = &types.RuleStatusDeny
	case "allow":
		ret = &types.RuleStatusAllow
	case "continue":
		ret = nil
	}
	return
}

func (matcher *AuditConfigValidationRule) IsMatching(object *AzureObject) bool {
	if matcher.customFunction != nil {
		return matcher.runFunc(object)
	}

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

func (matcher *AuditConfigValidationRule) runFunc(object *AzureObject) bool {
	vmLock.Lock()
	defer vmLock.Unlock()

	if err := vm.Set("obj", *object); err != nil {
		panic(err)
	}

	result, err := vm.Run(matcher.customFunction)
	if err != nil {
		panic(err)
	}

	status, err := result.ToBoolean()
	if err != nil {
		panic(err)
	}
	return status
}

package auditor

import (
	"regexp"
	"strings"
)

type (
	AuditConfigMatcherString struct {
		Match   *string        `yaml:"match,omitempty"`
		MatchRe *string        `yaml:"regexp,omitempty"`
		matchRe *regexp.Regexp //nolint:structcheck,unused
	}
	AuditConfigMatcherStringInternal struct {
		Match   *string        `yaml:"match"`
		MatchRe *string        `yaml:"regexp"`
		matchRe *regexp.Regexp //nolint:structcheck,unused
	}

	AuditConfigMatcherList struct {
		List *[]string `yaml:"list"`
	}
	AuditConfigMatcherListInternal struct {
		List *[]string `yaml:"list"`
	}

	AuditConfigMatcherAction struct {
		Action string `yaml:"action,omitempty"`
		status *bool
	}
)

func (matcher *AuditConfigMatcherString) UnmarshalYAML(unmarshal func(interface{}) error) error {
	val := AuditConfigMatcherStringInternal{}
	err := unmarshal(&val)
	if err != nil {
		val := ""
		err := unmarshal(&val)
		if err != nil {
			return err
		}
		if len(val) > 0 {
			matcher.Match = &val
		}
	} else {
		matcher.Match = val.Match
		matcher.MatchRe = val.MatchRe
		if matcher.MatchRe != nil {
			matcher.matchRe = regexp.MustCompile(*matcher.MatchRe)
		}
	}
	return nil
}

func (matcher *AuditConfigMatcherList) UnmarshalYAML(unmarshal func(interface{}) error) error {
	val := AuditConfigMatcherListInternal{}
	err := unmarshal(&val)
	if err != nil {
		val := []string{}
		err := unmarshal(&val)
		if err != nil {
			return err
		}
		if len(val) > 0 {
			matcher.List = &val
		}
	} else {
		matcher.List = val.List
	}
	return nil
}

func (matcher *AuditConfigMatcherString) IsMatching(value string) bool {
	if matcher.Match == nil && matcher.MatchRe == nil {
		// config is no set -> always matching
		return true
	}

	if matcher.Match != nil && strings.EqualFold(*matcher.Match, value) {
		return true
	}

	if matcher.MatchRe != nil && matcher.matchRe.MatchString(value) {
		return true
	}

	return false
}

func (matcher *AuditConfigMatcherList) IsMatching(valueList []string) bool {
	if matcher.List == nil {
		// matcher is not set -> always matching
		return true
	}

valueListLoop:
	for _, value := range valueList {
		for _, matchValue := range *matcher.List {
			if strings.EqualFold(matchValue, value) {
				continue valueListLoop
			}
		}
		return false
	}

	return true
}

func (action *AuditConfigMatcherAction) UnmarshalYAML(unmarshal func(interface{}) error) error {
	val := struct{ Action string }{}
	err := unmarshal(&val)
	if err != nil {
		val := ""
		err := unmarshal(&val)
		if err != nil {
			return err
		}
		if len(val) > 0 {
			action.Action = strings.ToLower(val)
		}
	} else {
		action.Action = strings.ToLower(val.Action)
	}

	status := true
	switch action.Action {
	case "deny":
		status = false
	case "", "allow":
		status = true
	default:
		panic("invalid action \"" + action.Action + "\" found, only \"deny\" and \"allow\" are valid")
	}
	action.status = &status

	return nil
}

func (action *AuditConfigMatcherAction) ValidationStatus() bool {
	if action.status == nil {
		status := true
		action.status = &status
		action.Action = "allow"
	}

	return *action.status
}

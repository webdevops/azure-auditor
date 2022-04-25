package validator

import (
	"regexp"
	"strings"
	"time"
)

type (
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
		} else if field.AnyOf != nil {
			for _, match := range *field.AnyOf {
				if strings.EqualFold(match, fieldValue) {
					return true, true
				}
			}
			return false, false
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

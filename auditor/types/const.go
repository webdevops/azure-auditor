package types

import (
	"strings"
)

type RuleStatus int

var (
	RuleStatusIgnore RuleStatus = -1
	RuleStatusDeny   RuleStatus = 0
	RuleStatusAllow  RuleStatus = 1
)

func StringToRuleStatus(val string) RuleStatus {
	val = strings.TrimSpace(val)
	val = strings.ToLower(val)

	switch strings.ToLower(val) {
	case "-1", "ignore":
		return RuleStatusIgnore
	case "0", "false", "deny":
		return RuleStatusDeny
	case "1", "true", "allow":
		return RuleStatusAllow
	}
	return RuleStatusDeny
}

func (s RuleStatus) String() (ret string) {
	ret = "unknown"
	switch s {
	case RuleStatusIgnore:
		ret = "ignore"
	case RuleStatusDeny:
		ret = "deny"
	case RuleStatusAllow:
		ret = "allow"
	}
	return
}

func (s RuleStatus) IsIgnore() bool {
	return s == RuleStatusIgnore
}
func (s RuleStatus) IsDeny() bool {
	return s == RuleStatusDeny
}
func (s RuleStatus) IsAllow() bool {
	return s == RuleStatusAllow
}

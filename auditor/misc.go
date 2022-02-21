package auditor

import "strings"

func cronspecIsValid(cronspec string) bool {
	switch strings.ToLower(cronspec) {
	case "", "0", "no", "n", "false":
		return false
	default:
		return true
	}
}

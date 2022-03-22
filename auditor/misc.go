package auditor

import (
	"strings"

	"github.com/Azure/go-autorest/autorest/to"
)

func cronspecIsValid(cronspec string) bool {
	switch strings.ToLower(cronspec) {
	case "", "0", "no", "n", "false":
		return false
	default:
		return true
	}
}

func stringPtrToStringLower(val *string) string {
	return strings.ToLower(to.String(val))
}

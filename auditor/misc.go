package auditor

import (
	"regexp"
	"strings"
)

type (
	azureResoruceInfo struct {
		SubscriptionID string
		ResourceGroup  string
	}
)

var (
	azureInfoRegexp = regexp.MustCompile(`(?i)subscriptions/([^/]+)/resourceGroups/([^/]+)(/.+)?$`)
)

func extractAzureResourceInfo(val string) (resource azureResoruceInfo) {
	match := azureInfoRegexp.FindStringSubmatch(val)
	if len(match) >= 2 {
		resource.SubscriptionID = match[1]
	}

	if len(match) >= 3 {
		resource.ResourceGroup = match[2]
	}

	return
}

func cronspecIsValid(cronspec string) bool {
	switch strings.ToLower(cronspec) {
	case "", "0", "no", "n", "false":
		return false
	default:
		return true
	}
}

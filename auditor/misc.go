package auditor

import (
	"strings"

	"github.com/webdevops/go-common/utils/to"
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

func azureTagsToAzureObjectField(tags map[string]*string) map[string]interface{} {
	ret := map[string]interface{}{}
	for tagName, tagValue := range to.StringMap(tags) {
		ret[tagName] = tagValue
	}
	return ret
}

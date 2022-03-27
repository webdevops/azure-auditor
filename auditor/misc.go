package auditor

import (
	"strings"

	"github.com/Azure/go-autorest/autorest/to"
	flatten "github.com/jeremywohl/flatten/v2"
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

func interfaceToString(value interface{}) string {
	switch val := value.(type) {
	case string:
		return val
	case *string:
		return to.String(val)
	}
	return ""
}

func newAzureObject(data map[string]interface{}) *AzureObject {
	obj := AzureObject{}

	dataFlat, _ := flattenMap(data)
	for name, val := range dataFlat {
		obj[name] = val
	}

	return &obj
}

func flattenMap(src map[string]interface{}) (map[string]interface{}, error) {
	return flatten.Flatten(src, "", flatten.DotStyle)
}

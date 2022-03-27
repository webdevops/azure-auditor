package auditor

import (
	"strings"
)

type (
	AzureObject map[string]interface{}
)

func (o *AzureObject) ResourceID() string {
	if val, ok := (*o)["resourceID"].(string); ok {
		return val
	}
	return ""
}

func (o *AzureObject) ToPrometheusLabel(name string) string {
	if val, ok := (*o)[name]; ok {
		switch v := val.(type) {
		case string:
			return v
		case []string:
			return strings.Join(v, ",")
		}
	}

	return ""
}

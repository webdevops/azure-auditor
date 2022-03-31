package validator

import (
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/jeremywohl/flatten/v2"
)

var (
	timeFormats = []string{
		// preferred format
		time.RFC3339,

		// human format
		"2006-01-02 15:04:05 +07:00",
		"2006-01-02 15:04:05 MST",
		"2006-01-02 15:04:05",

		// allowed formats
		time.RFC822,
		time.RFC822Z,
		time.RFC850,
		time.RFC1123,
		time.RFC1123Z,
		time.RFC3339Nano,

		// least preferred format
		"2006-01-02",
	}
)

func interfaceToString(value interface{}) string {
	switch val := value.(type) {
	case string:
		return val
	case *string:
		return to.String(val)
	}
	return ""
}

func interfaceListToStringList(value []interface{}) []string {
	list := []string{}
	for _, val := range value {
		list = append(list, interfaceToString(val))
	}
	return list
}

func flattenMap(src map[string]interface{}) (map[string]interface{}, error) {
	return flatten.Flatten(src, "", flatten.DotStyle)
}

func stringListIsMatchingAllOf(list, matcherList []string) bool {
	matchCount := int(0)
	for _, match := range matcherList {
		for _, val := range list {
			if strings.EqualFold(val, match) {
				matchCount++
			}
		}
	}
	return matchCount == len(matcherList) && matchCount == len(list)
}

func stringListIsMatchingAnyOf(list, matcherList []string) bool {
	for _, match := range matcherList {
		for _, val := range list {
			if strings.EqualFold(val, match) {
				return true
			}
		}
	}

	return false
}

func parseTime(value string) (parsedTime *time.Time) {
	// parse time
	for _, timeFormat := range timeFormats {
		if parseVal, parseErr := time.Parse(timeFormat, value); parseErr == nil && parseVal.Unix() > 0 {
			parsedTime = &parseVal
			return
		}
	}
	return
}

package auditor

import (
	"crypto/sha1" // #nosec G505
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/webdevops/go-common/utils/to"
	yaml "sigs.k8s.io/yaml"

	"github.com/webdevops/azure-auditor/auditor/types"
	"github.com/webdevops/azure-auditor/auditor/validator"
)

var (
	yamlCleanupRegexp = regexp.MustCompile(`(?im)^([^:]+)[\s]*:[\s]*"(.+)"$`)
)

type (
	AzureAuditorReport struct {
		Summary    *AzureAuditorReportSummary
		Lines      []*AzureAuditorReportLine
		UpdateTime *time.Time
		lock       *sync.Mutex
	}

	AzureAuditorReportSummary struct {
		Ignore int64
		Deny   int64
		Allow  int64
	}

	AzureAuditorReportLine struct {
		Resource AzureAuditorReportLineResource `json:"resource"`
		RuleID   string                         `json:"rule"`
		GroupBy  interface{}                    `json:"groupBy"`
		Status   string                         `json:"status"`
		Count    uint64                         `json:"count"`
	}

	AzureAuditorReportLineResource map[string]interface{}
)

func NewAzureAuditorReport() *AzureAuditorReport {
	report := &AzureAuditorReport{}
	report.lock = &sync.Mutex{}
	report.Summary = &AzureAuditorReportSummary{}
	report.Lines = []*AzureAuditorReportLine{}
	return report
}

func (reportLine *AzureAuditorReportLine) Hash() [20]byte {
	hashData, _ := json.Marshal(reportLine)
	return sha1.Sum(hashData) // #nosec G401
}

func (reportLine *AzureAuditorReportLine) MarshalJSON() ([]byte, error) {
	data := map[string]interface{}{}

	resourceInfo, _ := reportLine.Resource.MarshalJSON()
	data["resource"] = yamlCleanupRegexp.ReplaceAllString(string(resourceInfo), "$1: $2")
	data["rule"] = reportLine.RuleID
	data["status"] = reportLine.Status
	data["groupBy"] = reportLine.GroupBy
	data["count"] = reportLine.Count

	return json.Marshal(data)
}

func (report *AzureAuditorReport) Clear() {
	report.lock.Lock()
	defer report.lock.Unlock()

	report.Lines = []*AzureAuditorReportLine{}
}

func (report *AzureAuditorReport) Add(resource *validator.AzureObject, ruleID string, status types.RuleStatus) {
	report.lock.Lock()
	defer report.lock.Unlock()

	report.Lines = append(
		report.Lines,
		&AzureAuditorReportLine{
			Resource: AzureAuditorReportLineResource(*resource),
			RuleID:   ruleID,
			Status:   status.String(),
		},
	)

	switch status {
	case types.RuleStatusIgnore:
		report.Summary.Ignore++
	case types.RuleStatusDeny:
		report.Summary.Deny++
	case types.RuleStatusAllow:
		report.Summary.Allow++
	}
}

func (resource *AzureAuditorReportLineResource) MarshalJSON() ([]byte, error) {
	lines := map[string]string{}

	for key, value := range *resource {
		switch v := value.(type) {
		case []*string:
			lines[key] = strings.Join(to.Slice(v), ", ")
		case []string:
			lines[key] = strings.Join(v, ", ")
		case map[string]interface{}:
			data, _ := yaml.Marshal(v)
			lines[key] = string(data)
		default:
			lines[key] = fmt.Sprintf("%v", v)
		}
	}

	keys := make([]string, 0, len(lines))
	for k := range lines {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	ret := ""
	for _, key := range keys {
		ret += fmt.Sprintf("%s: %s\n", key, lines[key])
	}

	return []byte(ret), nil
}

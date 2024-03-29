package auditor

import (
	"crypto/sha1" // #nosec G505
	"encoding/json"
	"regexp"
	"sync"
	"time"

	yaml "gopkg.in/yaml.v3"

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
		Resource map[string]interface{} `json:"resource"`
		RuleID   string                 `json:"rule"`
		GroupBy  interface{}            `json:"groupBy"`
		Status   string                 `json:"status"`
		Count    uint64                 `json:"count"`
	}
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

	resourceInfo, _ := yaml.Marshal(reportLine.Resource)
	data["resource"] = string(resourceInfo)
	data["rule"] = reportLine.RuleID
	data["status"] = reportLine.Status
	data["groupBy"] = reportLine.GroupBy
	data["count"] = reportLine.Count

	data["resource"] = yamlCleanupRegexp.ReplaceAllString(data["resource"].(string), "$1: $2")

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
			Resource: *resource,
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

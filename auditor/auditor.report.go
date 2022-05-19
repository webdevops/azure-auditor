package auditor

import (
	"encoding/json"
	"regexp"
	"sync"
	"time"

	yaml "gopkg.in/yaml.v3"

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
		Ok     int64
		Failed int64
	}

	AzureAuditorReportLine struct {
		Resource map[string]interface{} `json:"resource"`
		RuleID   string                 `json:"rule"`
		GroupBy  interface{}            `json:"groupBy"`
		Status   bool                   `json:"status"`
	}
)

func NewAzureAuditorReport() *AzureAuditorReport {
	report := &AzureAuditorReport{}
	report.lock = &sync.Mutex{}
	report.Summary = &AzureAuditorReportSummary{}
	report.Lines = []*AzureAuditorReportLine{}
	return report
}

func (reportLine *AzureAuditorReportLine) MarshalJSON() ([]byte, error) {
	data := map[string]interface{}{}

	resourceInfo, _ := yaml.Marshal(reportLine.Resource)
	data["resource"] = string(resourceInfo)
	data["rule"] = reportLine.RuleID
	data["status"] = reportLine.Status
	data["groupBy"] = reportLine.GroupBy

	data["resource"] = yamlCleanupRegexp.ReplaceAllString(data["resource"].(string), "$1: $2")

	return json.Marshal(data)
}

func (report *AzureAuditorReport) Clear() {
	report.lock.Lock()
	defer report.lock.Unlock()

	report.Lines = []*AzureAuditorReportLine{}
}

func (report *AzureAuditorReport) Add(resource *validator.AzureObject, ruleID string, status bool) {
	report.lock.Lock()
	defer report.lock.Unlock()

	report.Lines = append(
		report.Lines,
		&AzureAuditorReportLine{
			Resource: *resource,
			RuleID:   ruleID,
			Status:   status,
		},
	)

	if status {
		report.Summary.Ok++
	} else {
		report.Summary.Failed++
	}
}

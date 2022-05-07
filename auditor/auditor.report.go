package auditor

import (
	"encoding/json"
	"sync"

	yaml "gopkg.in/yaml.v3"

	"github.com/webdevops/azure-auditor/auditor/validator"
)

type (
	AzureAuditorReport struct {
		Summary *AzureAuditorReportSummary
		Lines   []*AzureAuditorReportLine
		lock    *sync.Mutex
	}

	AzureAuditorReportSummary struct {
		Ok     int64
		Failed int64
	}

	AzureAuditorReportLine struct {
		Resource map[string]interface{}
		RuleID   string
		GroupBy  interface{}
		Status   bool
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
	data["Resource"] = string(resourceInfo)
	data["RuleID"] = reportLine.RuleID
	data["Status"] = reportLine.Status
	data["GroupBy"] = reportLine.GroupBy

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

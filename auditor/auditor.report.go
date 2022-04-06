package auditor

import (
	"sync"

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

package auditor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	armoperationalinsights "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights/v2"
	log "github.com/sirupsen/logrus"
	azureCommon "github.com/webdevops/go-common/azuresdk/armclient"
	"github.com/webdevops/go-common/azuresdk/cloudconfig"
	prometheusCommon "github.com/webdevops/go-common/prometheus"
	"github.com/webdevops/go-common/utils/to"

	"github.com/webdevops/azure-auditor/auditor/validator"
)

const (
	OperationInsightsWorkspaceUrlSuffix = "/v1"
)

type (
	LogAnaltyicsQueryResult struct {
		Tables *[]struct {
			Name    string `json:"name"`
			Columns *[]struct {
				Name *string `json:"name"`
				Type *string `json:"type"`
			} `json:"columns"`
			Rows *[][]interface{} `json:"rows"`
		} `json:"tables"`
	}
)

func (auditor *AzureAuditor) auditLogAnalytics(ctx context.Context, logger *log.Entry, configName string, config *validator.AuditConfigValidation, report *AzureAuditorReport, callback chan<- func()) {
	list := auditor.queryLogAnalytics(ctx, logger, config)

	violationMetric := prometheusCommon.NewMetricsList()

	for _, object := range list {
		matchingRuleId, status := config.Validate(object)
		report.Add(object, matchingRuleId, status)

		if !status && config.IsMetricsEnabled() {
			violationMetric.AddInfo(
				config.CreatePrometheusMetricFromAzureObject(object, matchingRuleId),
			)
		}
	}

	callback <- func() {
		logger.Infof("found %v illegal LogAnalytics:%v", len(violationMetric.GetList()), configName)
		violationMetric.GaugeSetInc(auditor.prometheus.logAnalytics[configName])
	}
}

func (auditor *AzureAuditor) queryLogAnalytics(ctx context.Context, logger *log.Entry, config *validator.AuditConfigValidation) (list []*validator.AzureObject) {
	var (
		baseUrl string
	)

	switch auditor.azure.client.GetCloudName() {
	case cloudconfig.AzurePublicCloud:
		baseUrl = "https://api.loganalytics.io"
	case cloudconfig.AzureChinaCloud:
		baseUrl = "https://api.loganalytics.azure.cn"
	case cloudconfig.AzureGovernmentCloud:
		baseUrl = "https://api.loganalytics.us"
	}

	subscriptionList := auditor.getSubscriptionList(ctx)

	for _, mainWorkspaceResourceId := range *config.Workspaces {
		workspaceAuditList := []*validator.AzureObject{}

		workspaceLogger := logger.WithField("logAnalyticsWorkspace", mainWorkspaceResourceId)

		mainWorkspaceInfo, err := azureCommon.ParseResourceId(mainWorkspaceResourceId)
		if err != nil {
			workspaceLogger.Panic(err)
		}

		// lookup subscription from workspace id
		if v, ok := subscriptionList[mainWorkspaceInfo.Subscription]; ok {
			workspaceLogger = workspaceLogger.WithFields(log.Fields{
				"subscriptionID":   to.String(v.SubscriptionID),
				"subscriptionName": to.String(v.DisplayName),
			})
		}

		mainWorkspaceId, err := auditor.lookupWorkspaceResource(ctx, mainWorkspaceResourceId)
		if err != nil {
			workspaceLogger.Panic(err)
		}

		workspaces := []string{}

		if config.AdditionalWorkspaces != nil {
			for _, additionalWorkspaceResourceId := range *config.AdditionalWorkspaces {
				additionalWorkspaceId, err := auditor.lookupWorkspaceResource(ctx, additionalWorkspaceResourceId)
				if err != nil {
					workspaceLogger.Panic(err)
				}

				workspaces = append(workspaces, to.String(additionalWorkspaceId))
			}
		}

		scopeUrl := fmt.Sprintf("%s/.default", baseUrl)
		queryUrl := fmt.Sprintf("%s/v1/workspaces/%s/query", baseUrl, to.String(mainWorkspaceId))

		credToken, err := auditor.azure.client.GetCred().GetToken(ctx, policy.TokenRequestOptions{
			Scopes: []string{scopeUrl},
		})
		if err != nil {
			workspaceLogger.Error(err)
			return
		}

		// execute query
		workspaceLogger.WithField("workspaces", workspaces).Debug("sending query")
		startTime := time.Now()
		requestBody := struct {
			Query      *string   `json:"query"`
			Workspaces *[]string `json:"workspaces"`
			Timespan   *string   `json:"timespan"`
		}{
			Query:      config.Query,
			Workspaces: &workspaces,
			Timespan:   config.Timespan,
		}

		requestBodyBytes, err := json.Marshal(requestBody)
		if err != nil {
			log.Fatal(err)
		}
		bytes.NewBuffer(requestBodyBytes)

		req, err := http.NewRequest(http.MethodPost, queryUrl, bytes.NewBuffer(requestBodyBytes))
		if err != nil {
			log.Fatal(err)
		}
		req.Method = http.MethodPost
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("authorization", fmt.Sprintf("Bearer %s", credToken.Token))
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			workspaceLogger.Error(err)
			return
		}

		responseBody, err := io.ReadAll(response.Body)
		if err != nil {
			workspaceLogger.Error(err)
			return
		}

		var queryResults LogAnaltyicsQueryResult
		if err := json.Unmarshal(responseBody, &queryResults); err != nil {
			workspaceLogger.Error(err)
			return
		}

		// parse and process result
		resultTables := *queryResults.Tables
		for _, table := range resultTables {
			if table.Rows == nil || table.Columns == nil {
				// no results found, skip table
				continue
			}

			for _, v := range *table.Rows {
				auditLine := map[string]interface{}{}
				auditLine["resource.id"] = mainWorkspaceResourceId
				auditLine["subscription.id"] = mainWorkspaceInfo.Subscription
				for colNum, colName := range *resultTables[0].Columns {
					fieldName := to.String(colName.Name)
					fieldValue := v[colNum]

					if config.Mapping != nil {
						if targetField, ok := (*config.Mapping)[fieldName]; ok {
							auditLine[targetField] = fieldValue
						} else {
							auditLine[fieldName] = fieldValue
						}
					} else {
						auditLine[fieldName] = fieldValue
					}
				}
				workspaceAuditList = append(workspaceAuditList, validator.NewAzureObject(auditLine))
			}
		}
		workspaceLogger.WithField("workspaces", workspaces).Debugf("finished query, fetched %d rows after %s", len(workspaceAuditList), time.Since(startTime).String())

		if config.Enrich {
			auditor.enrichAzureObjects(ctx, nil, &workspaceAuditList)
		}

		list = append(list, workspaceAuditList...)
		time.Sleep(auditor.Opts.LogAnalytics.WaitTime)
	}

	return
}

func (auditor *AzureAuditor) lookupWorkspaceResource(ctx context.Context, resourceId string) (workspaceId *string, err error) {
	resourceInfo, err := azureCommon.ParseResourceId(resourceId)
	if err != nil {
		return nil, err
	}

	client, err := armoperationalinsights.NewWorkspacesClient(resourceInfo.Subscription, auditor.azure.client.GetCred(), auditor.azure.client.NewArmClientOptions())
	if err != nil {
		return nil, err
	}

	workspace, err := client.Get(ctx, resourceInfo.ResourceGroup, resourceInfo.ResourceName, nil)
	if err != nil {
		return nil, err
	}

	workspaceId = workspace.Properties.CustomerID
	return
}

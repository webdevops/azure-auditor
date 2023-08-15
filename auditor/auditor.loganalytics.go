package auditor

import (
	"context"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/monitor/azquery"
	armoperationalinsights "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights/v2"
	azureCommon "github.com/webdevops/go-common/azuresdk/armclient"
	prometheusCommon "github.com/webdevops/go-common/prometheus"
	"github.com/webdevops/go-common/utils/to"
	"go.uber.org/zap"

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

func (auditor *AzureAuditor) auditLogAnalytics(ctx context.Context, logger *zap.SugaredLogger, configName string, config *validator.AuditConfigValidation, report *AzureAuditorReport, callback chan<- func()) {
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

func (auditor *AzureAuditor) queryLogAnalytics(ctx context.Context, logger *zap.SugaredLogger, config *validator.AuditConfigValidation) (list []*validator.AzureObject) {

	subscriptionList := auditor.getSubscriptionList(ctx)

	for _, mainWorkspaceResourceId := range *config.Workspaces {
		workspaceAuditList := []*validator.AzureObject{}

		workspaceLogger := logger.With(zap.String("logAnalyticsWorkspace", mainWorkspaceResourceId))

		mainWorkspaceInfo, err := azureCommon.ParseResourceId(mainWorkspaceResourceId)
		if err != nil {
			workspaceLogger.Panic(err)
		}

		// lookup subscription from workspace id
		if v, ok := subscriptionList[mainWorkspaceInfo.Subscription]; ok {
			workspaceLogger = workspaceLogger.With(
				zap.String("subscriptionID", to.String(v.SubscriptionID)),
				zap.String("subscriptionName", to.String(v.DisplayName)),
			)
		}

		mainWorkspaceId, err := auditor.lookupWorkspaceResource(ctx, mainWorkspaceResourceId)
		if err != nil {
			workspaceLogger.Panic(err)
		}

		var workspaces []*string
		if config.AdditionalWorkspaces != nil {
			for _, additionalWorkspaceResourceId := range *config.AdditionalWorkspaces {
				additionalWorkspaceId, err := auditor.lookupWorkspaceResource(ctx, additionalWorkspaceResourceId)
				if err != nil {
					workspaceLogger.Panic(err)
				}

				workspaces = append(workspaces, additionalWorkspaceId)
			}
		}

		workspaceLogger.With(zap.Any("workspaces", workspaces)).Debug("sending query")
		startTime := time.Now()

		clientOpts := azquery.LogsClientOptions{ClientOptions: *auditor.azure.client.NewAzCoreClientOptions()}
		logsClient, err := azquery.NewLogsClient(auditor.azure.client.GetCred(), &clientOpts)
		if err != nil {
			workspaceLogger.Error(err)
			return
		}

		opts := azquery.LogsClientQueryWorkspaceOptions{}
		queryBody := azquery.Body{
			Query:                config.Query,
			Timespan:             (*azquery.TimeInterval)(config.Timespan),
			AdditionalWorkspaces: workspaces,
		}

		queryResults, err := logsClient.QueryWorkspace(ctx, *mainWorkspaceId, queryBody, &opts)
		if err != nil {
			workspaceLogger.Error(err)
			return
		}

		// parse and process result
		resultTables := queryResults.Tables
		for _, table := range resultTables {
			if table.Rows == nil || table.Columns == nil {
				// no results found, skip table
				continue
			}

			for _, v := range table.Rows {
				auditLine := map[string]interface{}{}
				auditLine["resource.id"] = mainWorkspaceResourceId
				auditLine["subscription.id"] = mainWorkspaceInfo.Subscription
				for colNum, colName := range resultTables[0].Columns {
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
		workspaceLogger.With(zap.Any("workspaces", workspaces)).Debugf("finished query, fetched %d rows after %s", len(workspaceAuditList), time.Since(startTime).String())

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

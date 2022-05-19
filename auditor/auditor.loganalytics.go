package auditor

import (
	"context"
	"time"

	operationalinsightsResource "github.com/Azure/azure-sdk-for-go/profiles/latest/operationalinsights/mgmt/operationalinsights"
	operationalinsightsQuery "github.com/Azure/azure-sdk-for-go/services/operationalinsights/v1/operationalinsights"
	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2021-01-01/subscriptions"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/Azure/go-autorest/autorest/to"
	log "github.com/sirupsen/logrus"
	azureCommon "github.com/webdevops/go-common/azure"
	prometheusCommon "github.com/webdevops/go-common/prometheus"

	"github.com/webdevops/azure-auditor/auditor/validator"
)

const (
	OperationInsightsWorkspaceUrlSuffix = "/v1"
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
	// Create and authorize a LogAnalytics client
	logAnalyticsClient := operationalinsightsQuery.NewQueryClientWithBaseURI(auditor.azure.client.Environment.ResourceIdentifiers.OperationalInsights + OperationInsightsWorkspaceUrlSuffix)
	authorizer, err := auth.NewAuthorizerFromEnvironmentWithResource(auditor.azure.client.Environment.ResourceIdentifiers.OperationalInsights)
	if err != nil {
		log.Panic(err)
	}
	auditor.decorateAzureClient(&logAnalyticsClient.Client, authorizer)

	subscriptionList := auditor.getSubscriptionList(ctx)

	for _, mainWorkspaceResourceId := range *config.Workspaces {
		var workspaceSubscription *subscriptions.Subscription
		workspaceAuditList := []*validator.AzureObject{}

		workspaceLogger := logger.WithField("logAnalyticsWorkspace", mainWorkspaceResourceId)

		mainWorkspaceInfo, err := azureCommon.ParseResourceId(mainWorkspaceResourceId)
		if err != nil {
			workspaceLogger.Panic(err)
		}

		// lookup subscription from workspace id
		if v, ok := subscriptionList[mainWorkspaceInfo.Subscription]; ok {
			workspaceSubscription = &v

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

		// execute query
		workspaceLogger.WithField("workspaces", workspaces).Debug("sending query")
		startTime := time.Now()
		queryBody := operationalinsightsQuery.QueryBody{
			Query:      config.Query,
			Timespan:   config.Timespan,
			Workspaces: &workspaces,
		}
		var queryResults, queryErr = logAnalyticsClient.Execute(ctx, *mainWorkspaceId, queryBody)
		if queryErr != nil {
			workspaceLogger.Error(queryErr.Error())
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
			auditor.enrichAzureObjects(ctx, workspaceSubscription, &workspaceAuditList)
		}

		list = append(list, workspaceAuditList...)
		time.Sleep(auditor.Opts.LogAnalytics.WaitTime)
	}

	return
}

func (auditor *AzureAuditor) lookupWorkspaceResource(ctx context.Context, resourceId string) (workspaceId *string, err error) {
	var resourceInfo *azureCommon.AzureResourceDetails
	resourceInfo, err = azureCommon.ParseResourceId(resourceId)
	if err != nil {
		return
	}

	client := operationalinsightsResource.NewWorkspacesClientWithBaseURI(auditor.azure.client.Environment.ResourceManagerEndpoint, resourceInfo.Subscription)
	auditor.decorateAzureClient(&client.Client, auditor.azure.client.Authorizer)

	workspace, azureErr := client.Get(ctx, resourceInfo.ResourceGroup, resourceInfo.ResourceName)
	if azureErr != nil {
		err = azureErr
		return
	}
	workspaceId = workspace.CustomerID

	return
}

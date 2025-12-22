package auditor

import (
	"context"
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/webdevops/go-common/log/slogger"
	prometheusCommon "github.com/webdevops/go-common/prometheus"

	"github.com/webdevops/azure-auditor/auditor/validator"
)

const (
	ResourceGraphQueryOptionsTop = 1000
)

func (auditor *AzureAuditor) auditResourceGraph(ctx context.Context, logger *slogger.Logger, subscription *armsubscriptions.Subscription, configName string, config *validator.AuditConfigValidation, report *AzureAuditorReport, callback chan<- func()) {
	list := auditor.queryResourceGraph(ctx, logger, subscription, config)

	violationMetric := prometheusCommon.NewMetricsList()

	for _, object := range list {
		matchingRuleId, status := config.Validate(object)
		report.Add(object, matchingRuleId, status)

		if status.IsDeny() && config.IsMetricsEnabled() {
			violationMetric.AddInfo(
				config.CreatePrometheusMetricFromAzureObject(object, matchingRuleId),
			)
		}
	}

	callback <- func() {
		logger.Info("found illegal ResourceGraph resources", slog.Int("violations", len(violationMetric.GetList())))
		violationMetric.GaugeSetInc(auditor.prometheus.resourceGraph[configName])
	}
}

func (auditor *AzureAuditor) queryResourceGraph(ctx context.Context, logger *slogger.Logger, subscription *armsubscriptions.Subscription, config *validator.AuditConfigValidation) (list []*validator.AzureObject) {
	client, err := armresourcegraph.NewClient(auditor.azure.client.GetCred(), nil)
	if err != nil {
		logger.Panic(err.Error())
	}

	queryFormat := armresourcegraph.ResultFormatObjectArray
	queryTop := int32(ResourceGraphQueryOptionsTop)
	queryRequest := armresourcegraph.QueryRequest{
		Query: config.Query,
		Options: &armresourcegraph.QueryRequestOptions{
			ResultFormat: &queryFormat,
			Top:          &queryTop,
		},
		Subscriptions: []*string{subscription.SubscriptionID},
	}

	result, err := client.Resources(ctx, queryRequest, nil)
	if err != nil {
		logger.Panic(err.Error())
	}

	for {
		logger.Debug("parsing result")

		if resultList, ok := result.Data.([]interface{}); ok {
			// check if we got data, otherwise break the for loop
			if len(resultList) == 0 {
				break
			}

			for _, v := range resultList {
				if resultRow, ok := v.(map[string]interface{}); ok {
					auditLine := map[string]interface{}{}

					if config.Mapping != nil {
						mapping := *config.Mapping
						for rowKey, rowVal := range resultRow {
							if targetField, ok := mapping[rowKey]; ok {
								auditLine[targetField] = rowVal
							} else {
								auditLine[rowKey] = rowVal
							}
						}
					} else {
						auditLine = resultRow
					}

					list = append(list, validator.NewAzureObject(auditLine))
				}
			}
		}

		if result.SkipToken != nil {
			queryRequest.Options.SkipToken = result.SkipToken
			result, err = client.Resources(ctx, queryRequest, nil)
			if err != nil {
				logger.Panic(err.Error())
			}
		} else {
			break
		}
	}

	if config.Enrich {
		auditor.enrichAzureObjects(ctx, subscription, &list)
	}

	return
}

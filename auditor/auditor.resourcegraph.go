package auditor

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	resourcegraph "github.com/Azure/azure-sdk-for-go/services/resourcegraph/mgmt/2019-04-01/resourcegraph"
	log "github.com/sirupsen/logrus"
	prometheusCommon "github.com/webdevops/go-common/prometheus"

	"github.com/webdevops/azure-auditor/auditor/validator"
)

const (
	ResourceGraphQueryOptionsTop = 1000
)

func (auditor *AzureAuditor) auditResourceGraph(ctx context.Context, logger *log.Entry, subscription *subscriptions.Subscription, configName string, config *validator.AuditConfigValidation, report *AzureAuditorReport, callback chan<- func()) {
	list := auditor.queryResourceGraph(ctx, logger, subscription, config)

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
		logger.Infof("found %v illegal ResourceGraph:%v", len(violationMetric.GetList()), configName)
		violationMetric.GaugeSetInc(auditor.prometheus.resourceGraph[configName])
	}
}

func (auditor *AzureAuditor) queryResourceGraph(ctx context.Context, logger *log.Entry, subscription *subscriptions.Subscription, config *validator.AuditConfigValidation) (list []*validator.AzureObject) {
	// Create and authorize a ResourceGraph client
	resourcegraphClient := resourcegraph.NewWithBaseURI(auditor.azure.client.Environment.ResourceManagerEndpoint)
	auditor.decorateAzureClient(&resourcegraphClient.Client, auditor.azure.client.GetAuthorizer())

	requestQueryTop := int32(ResourceGraphQueryOptionsTop)
	requestQuerySkip := int32(0)

	// Set options
	RequestOptions := resourcegraph.QueryRequestOptions{
		ResultFormat: "objectArray",
		Top:          &requestQueryTop,
		Skip:         &requestQuerySkip,
	}

	// Create the query request
	resultTotalRecords := int32(0)
	for {
		Request := resourcegraph.QueryRequest{
			Subscriptions: &[]string{
				*subscription.SubscriptionID,
			},
			Query:   config.Query,
			Options: &RequestOptions,
		}

		var results, queryErr = resourcegraphClient.Resources(ctx, Request)
		if results.TotalRecords != nil {
			resultTotalRecords = int32(*results.TotalRecords)
		}
		if queryErr == nil {
			logger.Debug("parsing result")

			if resultList, ok := results.Data.([]interface{}); ok {
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
		} else {
			logger.Error(queryErr)
		}

		*RequestOptions.Skip += requestQueryTop
		if *RequestOptions.Skip >= resultTotalRecords {
			break
		}
	}

	if config.Enrich {
		auditor.enrichAzureObjects(ctx, subscription, &list)
	}

	return
}

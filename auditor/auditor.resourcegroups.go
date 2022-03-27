package auditor

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	prometheusCommon "github.com/webdevops/go-prometheus-common"
)

func (auditor *AzureAuditor) auditResourceGroups(ctx context.Context, logger *log.Entry, subscription *subscriptions.Subscription, report *AzureAuditorReport, callback chan<- func()) {
	list := auditor.fetchResourceGroups(ctx, logger, subscription)

	violationMetric := prometheusCommon.NewMetricsList()

	for _, object := range list {
		matchingRuleId, status := auditor.config.ResourceGroups.Validate(object)
		report.Add(object, matchingRuleId, status)

		if !status {
			violationMetric.AddInfo(prometheus.Labels{
				"subscriptionID": to.String(subscription.SubscriptionID),
				"resourceGroup":  object.ToPrometheusLabel("resourcegroup.name"),
				"location":       object.ToPrometheusLabel("resourcegroup.location"),
			})
		}
	}

	callback <- func() {
		logger.Infof("found %v illegal ResourceGroups", len(violationMetric.GetList()))
		violationMetric.GaugeSet(auditor.prometheus.resourceGroup)
	}
}

func (auditor *AzureAuditor) fetchResourceGroups(ctx context.Context, logger *log.Entry, subscription *subscriptions.Subscription) (list []*AzureObject) {
	client := resources.NewGroupsClientWithBaseURI(auditor.azure.environment.ResourceManagerEndpoint, *subscription.SubscriptionID)
	auditor.decorateAzureClient(&client.Client, auditor.azure.authorizer)

	result, err := client.ListComplete(ctx, "", nil)
	if err != nil {
		logger.Panic(err)
	}

	for _, item := range *result.Response().Value {
		tags := map[string]interface{}{}
		for tagName, tagValue := range to.StringMap(item.Tags) {
			tags[tagName] = tagValue
		}

		list = append(
			list,
			newAzureObject(
				map[string]interface{}{
					"resourceID":        stringPtrToStringLower(item.ID),
					"subscription.ID":   to.String(subscription.SubscriptionID),
					"subscription.name": to.String(subscription.DisplayName),

					"resourcegroup.name":     stringPtrToStringLower(item.Name),
					"resourcegroup.location": stringPtrToStringLower(item.Location),
					"resourcegroup.tag":      tags,
				},
			),
		)
	}

	return
}

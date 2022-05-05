package auditor

import (
	"context"

	"github.com/webdevops/azure-auditor/auditor/validator"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	prometheusCommon "github.com/webdevops/go-common/prometheus"
)

func (auditor *AzureAuditor) auditResourceGroups(ctx context.Context, logger *log.Entry, subscription *subscriptions.Subscription, report *AzureAuditorReport, callback chan<- func()) {
	list := auditor.fetchResourceGroups(ctx, logger, subscription)

	violationMetric := prometheusCommon.NewMetricsList()

	for _, object := range list {
		matchingRuleId, status := auditor.config.ResourceGroups.Validate(object)
		report.Add(object, matchingRuleId, status)

		if !status && auditor.config.ResourceGroups.IsMetricsEnabled() {
			violationMetric.AddInfo(prometheus.Labels{
				"subscriptionID":   object.ToPrometheusLabel("subscription.id"),
				"subscriptionName": object.ToPrometheusLabel("subscription.name"),
				"resourceGroup":    object.ToPrometheusLabel("resourcegroup.name"),
				"location":         object.ToPrometheusLabel("resourcegroup.location"),
				"rule":             matchingRuleId,
			})
		}
	}

	callback <- func() {
		logger.Infof("found %v illegal ResourceGroups", len(violationMetric.GetList()))
		violationMetric.GaugeSet(auditor.prometheus.resourceGroup)
	}
}

func (auditor *AzureAuditor) fetchResourceGroups(ctx context.Context, logger *log.Entry, subscription *subscriptions.Subscription) (list []*validator.AzureObject) {
	client := resources.NewGroupsClientWithBaseURI(auditor.azure.client.Environment.ResourceManagerEndpoint, *subscription.SubscriptionID)
	auditor.decorateAzureClient(&client.Client, auditor.azure.client.Authorizer)

	result, err := client.ListComplete(ctx, "", nil)
	if err != nil {
		logger.Panic(err)
	}

	for _, item := range *result.Response().Value {
		obj := map[string]interface{}{
			"resource.id":       stringPtrToStringLower(item.ID),
			"subscription.id":   to.String(subscription.SubscriptionID),
			"subscription.name": to.String(subscription.DisplayName),

			"resourcegroup.name":     stringPtrToStringLower(item.Name),
			"resourcegroup.location": stringPtrToStringLower(item.Location),
			"resourcegroup.tag":      azureTagsToAzureObjectField(item.Tags),
		}

		list = append(list, validator.NewAzureObject(obj))
	}

	auditor.enrichAzureObjects(ctx, subscription, &list)

	return
}

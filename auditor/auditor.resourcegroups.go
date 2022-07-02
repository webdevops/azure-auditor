package auditor

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"

	"github.com/webdevops/azure-auditor/auditor/validator"

	"github.com/Azure/go-autorest/autorest/to"
	log "github.com/sirupsen/logrus"
	prometheusCommon "github.com/webdevops/go-common/prometheus"
)

func (auditor *AzureAuditor) auditResourceGroups(ctx context.Context, logger *log.Entry, subscription *armsubscriptions.Subscription, report *AzureAuditorReport, callback chan<- func()) {
	list := auditor.fetchResourceGroups(ctx, logger, subscription)

	violationMetric := prometheusCommon.NewMetricsList()

	for _, object := range list {
		matchingRuleId, status := auditor.config.ResourceGroups.Validate(object)
		report.Add(object, matchingRuleId, status)

		if !status && auditor.config.ResourceGroups.IsMetricsEnabled() {
			violationMetric.AddInfo(
				auditor.config.ResourceGroups.CreatePrometheusMetricFromAzureObject(object, matchingRuleId),
			)
		}
	}

	callback <- func() {
		logger.Infof("found %v illegal ResourceGroups", len(violationMetric.GetList()))
		violationMetric.GaugeSetInc(auditor.prometheus.resourceGroup)
	}
}

func (auditor *AzureAuditor) fetchResourceGroups(ctx context.Context, logger *log.Entry, subscription *armsubscriptions.Subscription) (list []*validator.AzureObject) {
	client, err := armresources.NewResourceGroupsClient(*subscription.SubscriptionID, auditor.azure.client.GetCred(), nil)
	if err != nil {
		logger.Panic(err)
	}

	pager := client.NewListPager(nil)
	for pager.More() {
		result, err := pager.NextPage(ctx)
		if err != nil {
			logger.Panic(err)
		}

		for _, resourceGroup := range result.ResourceGroupListResult.Value {
			obj := map[string]interface{}{
				"resource.id":       stringPtrToStringLower(resourceGroup.ID),
				"subscription.id":   to.String(subscription.SubscriptionID),
				"subscription.name": to.String(subscription.DisplayName),

				"resourcegroup.name":     stringPtrToStringLower(resourceGroup.Name),
				"resourcegroup.location": stringPtrToStringLower(resourceGroup.Location),
				"resourcegroup.tag":      azureTagsToAzureObjectField(resourceGroup.Tags),
			}

			list = append(list, validator.NewAzureObject(obj))
		}
	}

	auditor.enrichAzureObjects(ctx, subscription, &list)

	return
}

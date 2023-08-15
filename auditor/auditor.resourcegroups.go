package auditor

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"

	"github.com/webdevops/azure-auditor/auditor/validator"

	"github.com/Azure/go-autorest/autorest/to"
	prometheusCommon "github.com/webdevops/go-common/prometheus"
	"go.uber.org/zap"
)

func (auditor *AzureAuditor) auditResourceGroups(ctx context.Context, logger *zap.SugaredLogger, subscription *armsubscriptions.Subscription, report *AzureAuditorReport, callback chan<- func()) {
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

func (auditor *AzureAuditor) fetchResourceGroups(ctx context.Context, logger *zap.SugaredLogger, subscription *armsubscriptions.Subscription) (list []*validator.AzureObject) {
	resourceGroupList, err := auditor.azure.client.ListResourceGroups(ctx, *subscription.SubscriptionID)
	if err != nil {
		logger.Panic(err)
	}

	for _, resourceGroup := range resourceGroupList {
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

	auditor.enrichAzureObjects(ctx, subscription, &list)

	return
}

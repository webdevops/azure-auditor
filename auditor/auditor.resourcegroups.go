package auditor

import (
	"context"
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/webdevops/go-common/log/slogger"

	"github.com/webdevops/azure-auditor/auditor/validator"

	prometheusCommon "github.com/webdevops/go-common/prometheus"
	"github.com/webdevops/go-common/utils/to"
)

func (auditor *AzureAuditor) auditResourceGroups(ctx context.Context, logger *slogger.Logger, subscription *armsubscriptions.Subscription, report *AzureAuditorReport, callback chan<- func()) {
	list := auditor.fetchResourceGroups(ctx, logger, subscription)

	violationMetric := prometheusCommon.NewMetricsList()

	for _, object := range list {
		matchingRuleId, status := auditor.config.ResourceGroups.Validate(object)
		report.Add(object, matchingRuleId, status)

		if status.IsDeny() && auditor.config.ResourceGroups.IsMetricsEnabled() {
			violationMetric.AddInfo(
				auditor.config.ResourceGroups.CreatePrometheusMetricFromAzureObject(object, matchingRuleId),
			)
		}
	}

	callback <- func() {
		logger.Info("found illegal ResourceGroups", slog.Int("violations", len(violationMetric.GetList())))
		violationMetric.GaugeSetInc(auditor.prometheus.resourceGroup)
	}
}

func (auditor *AzureAuditor) fetchResourceGroups(ctx context.Context, logger *slogger.Logger, subscription *armsubscriptions.Subscription) (list []*validator.AzureObject) {
	resourceGroupList, err := auditor.azure.client.ListResourceGroups(ctx, *subscription.SubscriptionID)
	if err != nil {
		logger.Panic(err.Error())
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

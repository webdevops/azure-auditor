package auditor

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"go.uber.org/zap"

	"github.com/webdevops/azure-auditor/auditor/validator"

	prometheusCommon "github.com/webdevops/go-common/prometheus"
	"github.com/webdevops/go-common/utils/to"
)

func (auditor *AzureAuditor) auditResourceProviders(ctx context.Context, logger *zap.SugaredLogger, subscription *armsubscriptions.Subscription, report *AzureAuditorReport, callback chan<- func()) {
	list := auditor.fetchResourceProviders(ctx, logger, subscription)

	violationMetric := prometheusCommon.NewMetricsList()

	for _, object := range list {
		matchingRuleId, status := auditor.config.ResourceProviders.Validate(object)
		report.Add(object, matchingRuleId, status)

		if status.IsDeny() && auditor.config.ResourceProviders.IsMetricsEnabled() {
			violationMetric.AddInfo(
				auditor.config.ResourceProviders.CreatePrometheusMetricFromAzureObject(object, matchingRuleId),
			)
		}
	}

	callback <- func() {
		logger.Infof("found %v illegal ResourceProviders", len(violationMetric.GetList()))
		violationMetric.GaugeSetInc(auditor.prometheus.resourceProvider)
	}
}

func (auditor *AzureAuditor) fetchResourceProviders(ctx context.Context, logger *zap.SugaredLogger, subscription *armsubscriptions.Subscription) (list []*validator.AzureObject) {
	client, err := armresources.NewProvidersClient(*subscription.SubscriptionID, auditor.azure.client.GetCred(), nil)
	if err != nil {
		logger.Panic(err)
	}

	pager := client.NewListPager(nil)
	for pager.More() {
		result, err := pager.NextPage(ctx)
		if err != nil {
			logger.Panic(err)
		}

		for _, resourceProvider := range result.Value {
			if strings.EqualFold(to.String(resourceProvider.RegistrationState), "Registered") {
				obj := map[string]interface{}{
					"resource.id":     stringPtrToStringLower(resourceProvider.ID),
					"subscription.id": to.String(subscription.SubscriptionID),

					"provider.namespace": stringPtrToStringLower(resourceProvider.Namespace),
				}

				list = append(list, validator.NewAzureObject(obj))
			}
		}
	}

	auditor.enrichAzureObjects(ctx, subscription, &list)

	return
}

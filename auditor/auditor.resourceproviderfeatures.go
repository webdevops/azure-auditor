package auditor

import (
	"context"
	"log/slog"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armfeatures"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/webdevops/go-common/log/slogger"

	"github.com/webdevops/azure-auditor/auditor/validator"

	prometheusCommon "github.com/webdevops/go-common/prometheus"
	"github.com/webdevops/go-common/utils/to"
)

func (auditor *AzureAuditor) auditResourceProviderFeatures(ctx context.Context, logger *slogger.Logger, subscription *armsubscriptions.Subscription, report *AzureAuditorReport, callback chan<- func()) {
	list := auditor.fetchResourceProviderFeatures(ctx, logger, subscription)
	violationMetric := prometheusCommon.NewMetricsList()

	for _, object := range list {
		matchingRuleId, status := auditor.config.ResourceProviderFeatures.Validate(object)
		report.Add(object, matchingRuleId, status)

		if status.IsDeny() && auditor.config.ResourceProviderFeatures.IsMetricsEnabled() {
			violationMetric.AddInfo(
				auditor.config.ResourceProviderFeatures.CreatePrometheusMetricFromAzureObject(object, matchingRuleId),
			)
		}
	}

	callback <- func() {
		logger.Info("found illegal ResourceProviderFeatures", slog.Int("violations", len(violationMetric.GetList())))
		violationMetric.GaugeSetInc(auditor.prometheus.resourceProviderFeature)
	}
}

func (auditor *AzureAuditor) fetchResourceProviderFeatures(ctx context.Context, logger *slogger.Logger, subscription *armsubscriptions.Subscription) (list []*validator.AzureObject) {
	client, err := armfeatures.NewClient(*subscription.SubscriptionID, auditor.azure.client.GetCred(), nil)
	if err != nil {
		logger.Panic(err.Error())
	}

	pager := client.NewListAllPager(nil)
	for pager.More() {
		result, err := pager.NextPage(ctx)
		if err != nil {
			logger.Panic(err.Error())
		}

		for _, feature := range result.Value {
			if strings.EqualFold(to.String(feature.Properties.State), "Registered") {
				nameParts := strings.SplitN(stringPtrToStringLower(feature.Name), "/", 2)

				if len(nameParts) >= 2 {
					obj := map[string]interface{}{
						"resource.id":     stringPtrToStringLower(feature.ID),
						"subscription.id": to.String(subscription.SubscriptionID),

						"provider.namespace": nameParts[0],
						"provider.feature":   nameParts[1],
					}

					list = append(list, validator.NewAzureObject(obj))
				}
			}
		}
	}

	auditor.enrichAzureObjects(ctx, subscription, &list)

	return
}

package auditor

import (
	"context"
	"strings"

	"github.com/webdevops/azure-audit-exporter/auditor/validator"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/features"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	prometheusCommon "github.com/webdevops/go-prometheus-common"
)

func (auditor *AzureAuditor) auditResourceProviderFeatures(ctx context.Context, logger *log.Entry, subscription *subscriptions.Subscription, report *AzureAuditorReport, callback chan<- func()) {
	list := auditor.fetchResourceProviderFeatures(ctx, logger, subscription)
	violationMetric := prometheusCommon.NewMetricsList()

	for _, object := range list {
		matchingRuleId, status := auditor.config.ResourceProviderFeatures.Validate(object)
		report.Add(object, matchingRuleId, status)

		if !status {
			violationMetric.AddInfo(prometheus.Labels{
				"subscriptionID":    to.String(subscription.SubscriptionID),
				"providerNamespace": object.ToPrometheusLabel("provider.namespace"),
				"providerFeature":   object.ToPrometheusLabel("provider.feature"),
				"rule":              matchingRuleId,
			})
		}
	}

	callback <- func() {
		logger.Infof("found %v illegal ResourceProviderFeatures", len(violationMetric.GetList()))
		violationMetric.GaugeSet(auditor.prometheus.resourceProviderFeature)
	}
}

func (auditor *AzureAuditor) fetchResourceProviderFeatures(ctx context.Context, logger *log.Entry, subscription *subscriptions.Subscription) (list []*validator.AzureObject) {
	client := features.NewClientWithBaseURI(auditor.azure.environment.ResourceManagerEndpoint, *subscription.SubscriptionID)
	auditor.decorateAzureClient(&client.Client, auditor.azure.authorizer)

	result, err := client.ListAllComplete(ctx)
	if err != nil {
		logger.Panic(err)
	}

	for result.NotDone() {
		item := result.Value()

		if strings.EqualFold(to.String(item.Properties.State), "Registered") {
			nameParts := strings.SplitN(stringPtrToStringLower(item.Name), "/", 2)

			if len(nameParts) >= 2 {
				obj := map[string]interface{}{
					"resourceID":        stringPtrToStringLower(item.ID),
					"subscription.ID":   to.String(subscription.SubscriptionID),
					"subscription.name": to.String(subscription.DisplayName),

					"provider.namespace": nameParts[0],
					"provider.feature":   nameParts[1],
				}

				list = append(list, validator.NewAzureObject(obj))
			}
		}

		if result.NextWithContext(ctx) != nil {
			break
		}
	}

	return
}

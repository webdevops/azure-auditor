package auditor

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/features"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/prometheus/client_golang/prometheus"
	prometheusCommon "github.com/webdevops/go-prometheus-common"
	"strings"
)

type (
	ResourceProviderFeature struct {
		ResourceID string
		Namespace  string
		Feature    string
	}
)

func (auditor *AzureAuditor) auditResourceProviderFeatures(ctx context.Context, subscription *subscriptions.Subscription, callback chan<- func()) {
	list := auditor.fetchResourceProviderFeatures(ctx, subscription)
	violationMetric := prometheusCommon.NewMetricsList()

	for _, row := range list {
		if !auditor.config.ResourceProviderFeatures.Validate(row) {
			violationMetric.AddInfo(prometheus.Labels{
				"subscriptionID":    to.String(subscription.SubscriptionID),
				"providerNamespace": row.Namespace,
				"feature":           row.Feature,
			})
		}
	}

	callback <- func() {
		auditor.logger.Infof("found %v illegal ResourceProviderFeatures", len(violationMetric.GetList()))
		violationMetric.GaugeSet(auditor.prometheus.resourceProviderFeature)
	}
}

func (auditor *AzureAuditor) fetchResourceProviderFeatures(ctx context.Context, subscription *subscriptions.Subscription) (list []ResourceProviderFeature) {
	client := features.NewClientWithBaseURI(auditor.azure.environment.ResourceManagerEndpoint, *subscription.SubscriptionID)
	auditor.decorateAzureClient(&client.Client, auditor.azure.authorizer)

	result, err := client.ListAllComplete(ctx)
	if err != nil {
		auditor.logger.Panic(err)
	}

	for result.NotDone() {
		item := result.Value()

		if strings.EqualFold(to.String(item.Properties.State), "Registered") {
			nameParts := strings.SplitN(to.String(item.Name), "/", 2)

			if len(nameParts) >= 2 {
				list = append(
					list,
					ResourceProviderFeature{
						ResourceID: to.String(item.ID),
						Namespace:  nameParts[0],
						Feature:    nameParts[1],
					},
				)
			}
		}

		if result.NextWithContext(ctx) != nil {
			break
		}
	}

	return
}

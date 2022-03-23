package auditor

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/features"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/prometheus/client_golang/prometheus"
	prometheusCommon "github.com/webdevops/go-prometheus-common"
)

func (auditor *AzureAuditor) auditResourceProviderFeatures(ctx context.Context, subscription *subscriptions.Subscription, report *AzureAuditorReport, callback chan<- func()) {
	list := auditor.fetchResourceProviderFeatures(ctx, subscription)
	violationMetric := prometheusCommon.NewMetricsList()

	for _, row := range list {
		matchingRuleId, status := auditor.config.ResourceProviderFeatures.Validate(row)

		report.Add(map[string]string{
			"resourceID": row.ResourceID,
			"namespace":  row.Namespace,
			"feature":    row.Feature,
		}, matchingRuleId, status)

		if status {
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

func (auditor *AzureAuditor) fetchResourceProviderFeatures(ctx context.Context, subscription *subscriptions.Subscription) (list []AzureResourceProviderFeature) {
	client := features.NewClientWithBaseURI(auditor.azure.environment.ResourceManagerEndpoint, *subscription.SubscriptionID)
	auditor.decorateAzureClient(&client.Client, auditor.azure.authorizer)

	result, err := client.ListAllComplete(ctx)
	if err != nil {
		auditor.logger.Panic(err)
	}

	for result.NotDone() {
		item := result.Value()

		if strings.EqualFold(to.String(item.Properties.State), "Registered") {
			nameParts := strings.SplitN(stringPtrToStringLower(item.Name), "/", 2)

			if len(nameParts) >= 2 {
				list = append(
					list,
					AzureResourceProviderFeature{
						AzureBaseObject: &AzureBaseObject{
							ResourceID: stringPtrToStringLower(item.ID),
						},
						Namespace: nameParts[0],
						Feature:   nameParts[1],
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

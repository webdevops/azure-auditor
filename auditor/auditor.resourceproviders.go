package auditor

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/prometheus/client_golang/prometheus"
	prometheusCommon "github.com/webdevops/go-prometheus-common"
)

func (auditor *AzureAuditor) auditResourceProviders(ctx context.Context, subscription *subscriptions.Subscription, callback chan<- func()) {
	list := auditor.fetchResourceProviders(ctx, subscription)

	violationMetric := prometheusCommon.NewMetricsList()

	report := auditor.startReport(ReportResourceProviders)
	for _, row := range list {
		matchingRuleId, status := auditor.config.ResourceProviders.Validate(row)

		report.Add(map[string]string{
			"resourceID": row.ResourceID,
			"namespace":  row.Namespace,
		}, matchingRuleId, status)

		if status {
			violationMetric.AddInfo(prometheus.Labels{
				"subscriptionID":    to.String(subscription.SubscriptionID),
				"providerNamespace": row.Namespace,
			})
		}
	}

	callback <- func() {
		auditor.logger.Infof("found %v illegal ResourceProviders", len(violationMetric.GetList()))
		violationMetric.GaugeSet(auditor.prometheus.resourceProvider)
	}
}

func (auditor *AzureAuditor) fetchResourceProviders(ctx context.Context, subscription *subscriptions.Subscription) (list []AzureResourceProvider) {
	client := resources.NewProvidersClientWithBaseURI(auditor.azure.environment.ResourceManagerEndpoint, *subscription.SubscriptionID)
	auditor.decorateAzureClient(&client.Client, auditor.azure.authorizer)

	result, err := client.ListComplete(ctx, nil, "")
	if err != nil {
		auditor.logger.Panic(err)
	}

	for _, item := range *result.Response().Value {
		if strings.EqualFold(to.String(item.RegistrationState), "Registered") {
			list = append(
				list,
				AzureResourceProvider{
					AzureBaseObject: &AzureBaseObject{
						ResourceID: to.String(item.ID),
					},
					Namespace: to.String(item.Namespace),
				},
			)
		}
	}

	return
}

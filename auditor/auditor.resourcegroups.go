package auditor

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/prometheus/client_golang/prometheus"
	prometheusCommon "github.com/webdevops/go-prometheus-common"
)

func (auditor *AzureAuditor) auditResourceGroups(ctx context.Context, subscription *subscriptions.Subscription, report *AzureAuditorReport, callback chan<- func()) {
	list := auditor.fetchResourceGroups(ctx, subscription)

	violationMetric := prometheusCommon.NewMetricsList()

	for _, row := range list {
		matchingRuleId, status := auditor.config.ResourceGroups.Validate(row)

		report.Add(map[string]string{
			"resourceID": row.ResourceID,
		}, matchingRuleId, status)

		if status {
			violationMetric.AddInfo(prometheus.Labels{
				"subscriptionID": to.String(subscription.SubscriptionID),
				"name":           row.Name,
				"location":       row.Location,
			})
		}
	}

	callback <- func() {
		auditor.logger.WithField("subscription", *subscription.SubscriptionID).Infof("found %v illegal ResourceGroups", len(violationMetric.GetList()))
		violationMetric.GaugeSet(auditor.prometheus.resourceGroup)
	}
}

func (auditor *AzureAuditor) fetchResourceGroups(ctx context.Context, subscription *subscriptions.Subscription) (list []AzureResourceGroup) {
	client := resources.NewGroupsClientWithBaseURI(auditor.azure.environment.ResourceManagerEndpoint, *subscription.SubscriptionID)
	auditor.decorateAzureClient(&client.Client, auditor.azure.authorizer)

	result, err := client.ListComplete(ctx, "", nil)
	if err != nil {
		auditor.logger.Panic(err)
	}

	for _, item := range *result.Response().Value {
		list = append(
			list,
			AzureResourceGroup{
				AzureBaseObject: &AzureBaseObject{
					ResourceID: stringPtrToStringLower(item.ID),
				},
				Name:     stringPtrToStringLower(item.Name),
				Location: stringPtrToStringLower(item.Location),
				Tags:     to.StringMap(item.Tags),
			},
		)
	}

	return
}

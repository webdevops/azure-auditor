package auditor

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/prometheus/client_golang/prometheus"
	prometheusCommon "github.com/webdevops/go-prometheus-common"
)

type (
	ResourceGroup struct {
		Name     string
		Location string
		Tags     map[string]string
	}
)

func (auditor *AzureAuditor) auditResourceGroups(ctx context.Context, subscription *subscriptions.Subscription, callback chan<- func()) {
	list := auditor.fetchResourceGroups(ctx, subscription)

	violationMetric := prometheusCommon.NewMetricsList()

	for _, row := range list {
		if !auditor.config.ResourceGroups.Validate(row) {
			violationMetric.AddInfo(prometheus.Labels{
				"subscriptionID": to.String(subscription.SubscriptionID),
				"name":           row.Name,
				"location":       row.Location,
			})
		}
	}

	callback <- func() {
		auditor.logger.Infof("found %v illegal ResourceGroups", len(violationMetric.GetList()))
		violationMetric.GaugeSet(auditor.prometheus.resourceGroup)
	}
}

func (auditor *AzureAuditor) fetchResourceGroups(ctx context.Context, subscription *subscriptions.Subscription) (list []ResourceGroup) {
	client := resources.NewGroupsClientWithBaseURI(auditor.azure.environment.ResourceManagerEndpoint, *subscription.SubscriptionID)
	auditor.decorateAzureClient(&client.Client, auditor.azure.authorizer)

	result, err := client.ListComplete(ctx, "", nil)
	if err != nil {
		auditor.logger.Panic(err)
	}

	for _, item := range *result.Response().Value {
		list = append(
			list,
			ResourceGroup{
				Name:     to.String(item.Name),
				Location: to.String(item.Location),
				Tags:     to.StringMap(item.Tags),
			},
		)
	}

	return
}

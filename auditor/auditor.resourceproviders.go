package auditor

import (
	"context"
	"strings"

	"github.com/webdevops/azure-auditor/auditor/validator"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/go-autorest/autorest/to"
	log "github.com/sirupsen/logrus"
	prometheusCommon "github.com/webdevops/go-common/prometheus"
)

func (auditor *AzureAuditor) auditResourceProviders(ctx context.Context, logger *log.Entry, subscription *subscriptions.Subscription, report *AzureAuditorReport, callback chan<- func()) {
	list := auditor.fetchResourceProviders(ctx, logger, subscription)

	violationMetric := prometheusCommon.NewMetricsList()

	for _, object := range list {
		matchingRuleId, status := auditor.config.ResourceProviders.Validate(object)
		report.Add(object, matchingRuleId, status)

		if !status && auditor.config.ResourceProviders.IsMetricsEnabled() {
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

func (auditor *AzureAuditor) fetchResourceProviders(ctx context.Context, logger *log.Entry, subscription *subscriptions.Subscription) (list []*validator.AzureObject) {
	client := resources.NewProvidersClientWithBaseURI(auditor.azure.client.Environment.ResourceManagerEndpoint, *subscription.SubscriptionID)
	auditor.decorateAzureClient(&client.Client, auditor.azure.client.GetAuthorizer())

	result, err := client.ListComplete(ctx, nil, "")
	if err != nil {
		logger.Panic(err)
	}

	for _, item := range *result.Response().Value {
		if strings.EqualFold(to.String(item.RegistrationState), "Registered") {
			obj := map[string]interface{}{
				"resource.id":     stringPtrToStringLower(item.ID),
				"subscription.id": to.String(subscription.SubscriptionID),

				"provider.namespace": stringPtrToStringLower(item.Namespace),
			}

			list = append(list, validator.NewAzureObject(obj))
		}
	}

	auditor.enrichAzureObjects(ctx, subscription, &list)

	return
}

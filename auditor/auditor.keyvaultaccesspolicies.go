package auditor

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/to"
	log "github.com/sirupsen/logrus"
	prometheusCommon "github.com/webdevops/go-common/prometheus"

	azureCommon "github.com/webdevops/go-common/azuresdk/armclient"

	"github.com/webdevops/azure-auditor/auditor/validator"
)

func (auditor *AzureAuditor) auditKeyvaultAccessPolicies(ctx context.Context, logger *log.Entry, subscription *armsubscriptions.Subscription, report *AzureAuditorReport, callback chan<- func()) {
	list := auditor.fetchKeyvaultAccessPolicies(ctx, logger, subscription)
	violationMetric := prometheusCommon.NewMetricsList()

	for _, object := range list {
		matchingRuleId, status := auditor.config.KeyvaultAccessPolicies.Validate(object)
		report.Add(object, matchingRuleId, status)

		if !status && auditor.config.KeyvaultAccessPolicies.IsMetricsEnabled() {
			violationMetric.AddInfo(
				auditor.config.KeyvaultAccessPolicies.CreatePrometheusMetricFromAzureObject(object, matchingRuleId),
			)
		}
	}

	callback <- func() {
		logger.Infof("found %v illegal KeyVault AccessPolicies", len(violationMetric.GetList()))
		violationMetric.GaugeSetInc(auditor.prometheus.keyvaultAccessPolicies)
	}
}

func (auditor *AzureAuditor) fetchKeyvaultAccessPolicies(ctx context.Context, logger *log.Entry, subscription *armsubscriptions.Subscription) (list []*validator.AzureObject) {
	client, err := armkeyvault.NewVaultsClient(*subscription.SubscriptionID, auditor.azure.client.GetCred(), nil)
	if err != nil {
		logger.Panic(err)
	}

	pager := client.NewListPager(nil)
	for pager.More() {
		result, err := pager.NextPage(ctx)
		if err != nil {
			logger.Panic(err)
		}

		for _, item := range result.ResourceListResult.Value {
			resourceInfo, _ := azure.ParseResourceID(to.String(item.ID))

			keyvaultResource, err := client.Get(ctx, resourceInfo.ResourceGroup, resourceInfo.ResourceName, nil)
			if err != nil {
				logger.Panic(err)
			}

			if keyvaultResource.Properties.AccessPolicies != nil {
				for _, accessPolicy := range keyvaultResource.Properties.AccessPolicies {
					azureResource, _ := azureCommon.ParseResourceId(*item.ID)

					obj := map[string]interface{}{
						"resource.id":             stringPtrToStringLower(item.ID),
						"subscription.id":         to.String(subscription.SubscriptionID),
						"resourcegroup.name":      azureResource.ResourceGroup,
						"principal.applicationid": stringPtrToStringLower(accessPolicy.ApplicationID),
						"principal.objectid":      stringPtrToStringLower(accessPolicy.ObjectID),

						"keyvault.name": azureResource.ResourceName,

						"permissions.certificates": keyvaultCertificatePermissionsToStringList(accessPolicy.Permissions.Certificates),
						"permissions.secrets":      keyvaultSecretPermissionsToStringList(accessPolicy.Permissions.Secrets),
						"permissions.keys":         keyvaultKeyPermissionsToStringList(accessPolicy.Permissions.Keys),
						"permissions.storage":      keyvaultStoragePermissionsToStringList(accessPolicy.Permissions.Storage),
					}

					list = append(list, validator.NewAzureObject(obj))
				}
			}
		}
	}

	auditor.enrichAzureObjects(ctx, subscription, &list)

	return
}

func keyvaultCertificatePermissionsToStringList(val []*armkeyvault.CertificatePermissions) (list []string) {
	for _, row := range val {
		val := strings.ToLower(string(*row))
		list = append(list, val)
	}
	return
}

func keyvaultSecretPermissionsToStringList(val []*armkeyvault.SecretPermissions) (list []string) {
	for _, row := range val {
		val := strings.ToLower(string(*row))
		list = append(list, val)
	}
	return
}

func keyvaultKeyPermissionsToStringList(val []*armkeyvault.KeyPermissions) (list []string) {
	for _, row := range val {
		val := strings.ToLower(string(*row))
		list = append(list, val)
	}
	return
}

func keyvaultStoragePermissionsToStringList(val []*armkeyvault.StoragePermissions) (list []string) {
	for _, row := range val {
		val := strings.ToLower(string(*row))
		list = append(list, val)
	}
	return
}

package auditor

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/mgmt/keyvault"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	azureCommon "github.com/webdevops/go-common/azure"
	prometheusCommon "github.com/webdevops/go-common/prometheus"

	"github.com/webdevops/azure-auditor/auditor/validator"
)

func (auditor *AzureAuditor) auditKeyvaultAccessPolicies(ctx context.Context, logger *log.Entry, subscription *subscriptions.Subscription, report *AzureAuditorReport, callback chan<- func()) {
	list := auditor.fetchKeyvaultAccessPolicies(ctx, logger, subscription)
	violationMetric := prometheusCommon.NewMetricsList()

	for _, object := range list {
		matchingRuleId, status := auditor.config.KeyvaultAccessPolicies.Validate(object)
		report.Add(object, matchingRuleId, status)

		if !status && auditor.config.KeyvaultAccessPolicies.IsMetricsEnabled() {
			violationMetric.AddInfo(prometheus.Labels{
				"subscriptionID": to.String(subscription.SubscriptionID),
				"keyvault":       object.ToPrometheusLabel("keyvault.name"),
				"resourceGroup":  object.ToPrometheusLabel("keyvault.resourceGroup"),

				"principalType":          object.ToPrometheusLabel("principal.type"),
				"principalDisplayName":   object.ToPrometheusLabel("principal.displayName"),
				"principalObjectID":      object.ToPrometheusLabel("principal.objectID"),
				"principalApplicationID": object.ToPrometheusLabel("principal.applicationID"),

				"permissionsCertificates": object.ToPrometheusLabel("permissions.certificates"),
				"permissionsSecrets":      object.ToPrometheusLabel("permissions.secrets"),
				"permissionsKeys":         object.ToPrometheusLabel("permissions.keys"),
				"permissionsStorage":      object.ToPrometheusLabel("permissions.storage"),
				"rule":                    matchingRuleId,
			})
		}
	}

	callback <- func() {
		logger.Infof("found %v illegal KeyVault AccessPolicies", len(violationMetric.GetList()))
		violationMetric.GaugeSet(auditor.prometheus.keyvaultAccessPolicies)
	}
}

func (auditor *AzureAuditor) fetchKeyvaultAccessPolicies(ctx context.Context, logger *log.Entry, subscription *subscriptions.Subscription) (list []*validator.AzureObject) {
	client := keyvault.NewVaultsClientWithBaseURI(auditor.azure.client.Environment.ResourceManagerEndpoint, *subscription.SubscriptionID)
	auditor.decorateAzureClient(&client.Client, auditor.azure.client.Authorizer)

	result, err := client.ListComplete(ctx, nil)
	if err != nil {
		logger.Panic(err)
	}
	for _, item := range *result.Response().Value {
		resourceInfo, _ := azure.ParseResourceID(to.String(item.ID))
		keyvaultResource, err := client.Get(ctx, resourceInfo.ResourceGroup, to.String(item.Name))
		if err != nil {
			logger.Panic(err)
		}

		if keyvaultResource.Properties.AccessPolicies != nil {
			for _, accessPolicy := range *keyvaultResource.Properties.AccessPolicies {
				applicationId := ""
				if accessPolicy.ApplicationID != nil {
					applicationId = accessPolicy.ApplicationID.String()
				}

				azureResource, _ := azureCommon.ParseResourceId(*item.ID)

				obj := map[string]interface{}{
					"resource.ID":             stringPtrToStringLower(item.ID),
					"subscription.ID":         to.String(subscription.SubscriptionID),
					"resourcegroup.name":      azureResource.ResourceGroup,
					"principal.applicationID": applicationId,
					"principal.objectID":      stringPtrToStringLower(accessPolicy.ObjectID),

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

	auditor.enrichAzureObjects(ctx, subscription, &list)

	return
}

func keyvaultCertificatePermissionsToStringList(val *[]keyvault.CertificatePermissions) (list []string) {
	if val != nil {
		for _, row := range *val {
			val := strings.ToLower(string(row))
			list = append(list, val)
		}
	}
	return
}

func keyvaultSecretPermissionsToStringList(val *[]keyvault.SecretPermissions) (list []string) {
	if val != nil {
		for _, row := range *val {
			val := strings.ToLower(string(row))
			list = append(list, val)
		}
	}
	return
}

func keyvaultKeyPermissionsToStringList(val *[]keyvault.KeyPermissions) (list []string) {
	if val != nil {
		for _, row := range *val {
			val := strings.ToLower(string(row))
			list = append(list, val)
		}
	}
	return
}

func keyvaultStoragePermissionsToStringList(val *[]keyvault.StoragePermissions) (list []string) {
	if val != nil {
		for _, row := range *val {
			val := strings.ToLower(string(row))
			list = append(list, val)
		}
	}
	return
}

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
	prometheusCommon "github.com/webdevops/go-prometheus-common"
	prometheusAzure "github.com/webdevops/go-prometheus-common/azure"
)

func (auditor *AzureAuditor) auditKeyvaultAccessPolicies(ctx context.Context, logger *log.Entry, subscription *subscriptions.Subscription, report *AzureAuditorReport, callback chan<- func()) {
	list := auditor.fetchKeyvaultAccessPolicies(ctx, logger, subscription)
	violationMetric := prometheusCommon.NewMetricsList()

	for _, object := range list {
		matchingRuleId, status := auditor.config.KeyvaultAccessPolicies.Validate(object)
		report.Add(object, matchingRuleId, status)

		if !status {
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
			})
		}
	}

	callback <- func() {
		logger.Infof("found %v illegal KeyVault AccessPolicies", len(violationMetric.GetList()))
		violationMetric.GaugeSet(auditor.prometheus.keyvaultAccessPolicies)
	}
}

func (auditor *AzureAuditor) fetchKeyvaultAccessPolicies(ctx context.Context, logger *log.Entry, subscription *subscriptions.Subscription) (list []*AzureObject) {
	client := keyvault.NewVaultsClientWithBaseURI(auditor.azure.environment.ResourceManagerEndpoint, *subscription.SubscriptionID)
	auditor.decorateAzureClient(&client.Client, auditor.azure.authorizer)

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

				azureResource, _ := prometheusAzure.ParseResourceId(*item.ID)

				list = append(
					list,
					newAzureObject(
						map[string]interface{}{
							"resourceID":        stringPtrToStringLower(item.ID),
							"subscription.ID":   to.String(subscription.SubscriptionID),
							"subscription.name": to.String(subscription.DisplayName),

							"keyvault.name":          azureResource.ResourceName,
							"keyvault.resourceGroup": azureResource.ResourceGroup,

							"subscriptionID":   azureResource.Subscription,
							"subscriptionName": to.String(subscription.DisplayName),

							"principal.applicationID": applicationId,
							"principal.objectID":      stringPtrToStringLower(accessPolicy.ObjectID),

							"permissions.certificates": keyvaultCertificatePermissionsToStringList(accessPolicy.Permissions.Certificates),
							"permissions.secrets":      keyvaultSecretPermissionsToStringList(accessPolicy.Permissions.Secrets),
							"permissions.keys":         keyvaultKeyPermissionsToStringList(accessPolicy.Permissions.Keys),
							"permissions.storage":      keyvaultStoragePermissionsToStringList(accessPolicy.Permissions.Storage),
						},
					),
				)
			}
		}
	}

	auditor.lookupKeyvaultAccessPolicyPrincipals(ctx, &list)

	return
}

func (auditor *AzureAuditor) lookupKeyvaultAccessPolicyPrincipals(ctx context.Context, list *[]*AzureObject) {
	principalObjectIDMap := map[string]*MsGraphDirectoryObjectInfo{}
	for _, row := range *list {
		if principalObjectID, ok := (*row)["principal.objectID"].(string); ok && principalObjectID != "" {
			principalObjectIDMap[principalObjectID] = nil
		}
	}

	auditor.lookupPrincipalIdMap(ctx, &principalObjectIDMap)

	for key, row := range *list {
		if principalObjectID, ok := (*row)["principal.objectID"].(string); ok && principalObjectID != "" {
			if directoryObjectInfo, exists := principalObjectIDMap[principalObjectID]; exists && directoryObjectInfo != nil {
				(*(*list)[key])["principal.type"] = directoryObjectInfo.Type
				(*(*list)[key])["principal.displayName"] = directoryObjectInfo.DisplayName
				(*(*list)[key])["principal.applicationID"] = directoryObjectInfo.ApplicationId
				(*(*list)[key])["principal.objectID"] = directoryObjectInfo.ObjectId
			}
		}
	}
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

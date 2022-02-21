package auditor

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/mgmt/keyvault"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/prometheus/client_golang/prometheus"
	prometheusCommon "github.com/webdevops/go-prometheus-common"
	"strings"
)

func (auditor *AzureAuditor) auditKeyvaultAccessPolicies(ctx context.Context, subscription *subscriptions.Subscription, callback chan<- func()) {
	list := auditor.fetchKeyvaultAccessPolicies(ctx, subscription)
	violationMetric := prometheusCommon.NewMetricsList()

	for _, row := range list {
		if !auditor.config.KeyvaultAccessPolicies.Validate(row) {
			violationMetric.AddInfo(prometheus.Labels{
				"subscriptionID":          to.String(subscription.SubscriptionID),
				"keyvault":                row.Keyvault,
				"objectID":                row.ObjectID,
				"applicationID":           row.ApplicationID,
				"permissionsCertificates": strings.Join(row.Permissions.Certificates, ","),
				"permissionsSecrets":      strings.Join(row.Permissions.Secrets, ","),
				"permissionsKeys":         strings.Join(row.Permissions.Keys, ","),
				"permissionsStorage":      strings.Join(row.Permissions.Storage, ","),
			})
		}
	}

	callback <- func() {
		auditor.logger.Infof("found %v illegal KeyVault AccessPolicies", len(violationMetric.GetList()))
		violationMetric.GaugeSet(auditor.prometheus.keyvaultAccessPolicies)
	}
}

func (auditor *AzureAuditor) fetchKeyvaultAccessPolicies(ctx context.Context, subscription *subscriptions.Subscription) (list []AzureKeyvaultAccessPolicy) {
	client := keyvault.NewVaultsClientWithBaseURI(auditor.azure.environment.ResourceManagerEndpoint, *subscription.SubscriptionID)
	auditor.decorateAzureClient(&client.Client, auditor.azure.authorizer)

	result, err := client.ListComplete(ctx, nil)
	if err != nil {
		auditor.logger.Panic(err)
	}

	for _, item := range *result.Response().Value {
		resourceInfo, _ := azure.ParseResourceID(to.String(item.ID))
		keyvaultResource, err := client.Get(ctx, resourceInfo.ResourceGroup, to.String(item.Name))
		if err != nil {
			auditor.logger.Panic(err)
		}

		if keyvaultResource.Properties.AccessPolicies != nil {
			for _, accessPolicy := range *keyvaultResource.Properties.AccessPolicies {
				applicationId := ""
				if accessPolicy.ApplicationID != nil {
					applicationId = accessPolicy.ApplicationID.String()
				}
				list = append(
					list,
					AzureKeyvaultAccessPolicy{
						AzureBaseObject: &AzureBaseObject{
							ResourceID: to.String(item.ID),
						},
						Keyvault:      to.String(item.Name),
						ApplicationID: applicationId,
						ObjectID:      to.String(accessPolicy.ObjectID),
						Permissions: AzureKeyvaultAccessPolicyPermissions{
							Certificates: keyvaultCertificatePermissionsToStringList(accessPolicy.Permissions.Certificates),
							Secrets:      keyvaultSecretPermissionsToStringList(accessPolicy.Permissions.Secrets),
							Keys:         keyvaultKeyPermissionsToStringList(accessPolicy.Permissions.Keys),
							Storage:      keyvaultStoragePermissionsToStringList(accessPolicy.Permissions.Storage),
						},
					},
				)
			}
		}
	}

	return
}

func keyvaultCertificatePermissionsToStringList(val *[]keyvault.CertificatePermissions) (list []string) {
	if val != nil {
		for _, row := range *val {
			list = append(list, string(row))
		}
	}
	return
}

func keyvaultSecretPermissionsToStringList(val *[]keyvault.SecretPermissions) (list []string) {
	if val != nil {
		for _, row := range *val {
			list = append(list, string(row))
		}
	}
	return
}

func keyvaultKeyPermissionsToStringList(val *[]keyvault.KeyPermissions) (list []string) {
	if val != nil {
		for _, row := range *val {
			list = append(list, string(row))
		}
	}
	return
}

func keyvaultStoragePermissionsToStringList(val *[]keyvault.StoragePermissions) (list []string) {
	if val != nil {
		for _, row := range *val {
			list = append(list, string(row))
		}
	}
	return
}

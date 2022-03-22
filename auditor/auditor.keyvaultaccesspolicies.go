package auditor

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/mgmt/keyvault"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/prometheus/client_golang/prometheus"
	prometheusCommon "github.com/webdevops/go-prometheus-common"
	prometheusAzure "github.com/webdevops/go-prometheus-common/azure"
)

func (auditor *AzureAuditor) auditKeyvaultAccessPolicies(ctx context.Context, subscription *subscriptions.Subscription, callback chan<- func()) {
	list := auditor.fetchKeyvaultAccessPolicies(ctx, subscription)
	violationMetric := prometheusCommon.NewMetricsList()

	report := auditor.startReport(ReportKeyvaultAccessPolicies)
	for _, row := range list {
		matchingRuleId, status := auditor.config.KeyvaultAccessPolicies.Validate(*row)

		azureResource, _ := prometheusAzure.ParseResourceId(row.ResourceID)

		report.Add(map[string]string{
			"resourceID":    row.ResourceID,
			"keyvault":      row.Keyvault,
			"resourceGroup": azureResource.ResourceGroup,

			"principalType":          row.PrincipalType,
			"principalDisplayName":   row.PrincipalDisplayName,
			"principalObjectID":      row.PrincipalObjectID,
			"principalApplicationID": row.PrincipalApplicationID,

			"permissionsCertificates": strings.Join(row.Permissions.Certificates, ","),
			"permissionsSecrets":      strings.Join(row.Permissions.Secrets, ","),
			"permissionsKeys":         strings.Join(row.Permissions.Keys, ","),
			"permissionsStorage":      strings.Join(row.Permissions.Storage, ","),
		}, matchingRuleId, status)

		if status {
			violationMetric.AddInfo(prometheus.Labels{
				"subscriptionID": to.String(subscription.SubscriptionID),
				"keyvault":       row.Keyvault,
				"resourceGroup":  azureResource.ResourceGroup,

				"principalType":          row.PrincipalType,
				"principalDisplayName":   row.PrincipalDisplayName,
				"principalObjectID":      row.PrincipalObjectID,
				"principalApplicationID": row.PrincipalApplicationID,

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

func (auditor *AzureAuditor) fetchKeyvaultAccessPolicies(ctx context.Context, subscription *subscriptions.Subscription) (list []*AzureKeyvaultAccessPolicy) {
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
					&AzureKeyvaultAccessPolicy{
						AzureBaseObject: &AzureBaseObject{
							ResourceID: to.String(item.ID),
						},
						Keyvault:               to.String(item.Name),
						PrincipalApplicationID: applicationId,
						PrincipalObjectID:      to.String(accessPolicy.ObjectID),
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

	auditor.lookupKeyvaultAccessPolicyPrincipals(ctx, &list)

	return
}

func (auditor *AzureAuditor) lookupKeyvaultAccessPolicyPrincipals(ctx context.Context, list *[]*AzureKeyvaultAccessPolicy) {
	principalObjectIDMap := map[string]*MsGraphDirectoryObjectInfo{}
	for _, row := range *list {
		if row.PrincipalObjectID != "" {
			principalObjectIDMap[row.PrincipalObjectID] = nil
		}
	}

	auditor.lookupPrincipalIdMap(ctx, &principalObjectIDMap)

	for key, row := range *list {
		if directoryObjectInfo, exists := principalObjectIDMap[row.PrincipalObjectID]; exists && directoryObjectInfo != nil {
			(*list)[key].PrincipalType = directoryObjectInfo.Type
			(*list)[key].PrincipalDisplayName = directoryObjectInfo.DisplayName
			(*list)[key].PrincipalApplicationID = directoryObjectInfo.ApplicationId
			(*list)[key].PrincipalObjectID = directoryObjectInfo.ObjectId
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

package auditor

import (
	"context"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/azure-sdk-for-go/services/preview/authorization/mgmt/2020-04-01-preview/authorization"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/prometheus/client_golang/prometheus"
	prometheusCommon "github.com/webdevops/go-prometheus-common"
	prometheusAzure "github.com/webdevops/go-prometheus-common/azure"
)

func (auditor *AzureAuditor) auditRoleAssignments(ctx context.Context, subscription *subscriptions.Subscription, callback chan<- func()) {
	list := auditor.fetchRoleAssignments(ctx, subscription)

	violationMetric := prometheusCommon.NewMetricsList()

	report := auditor.startReport(ReportRoleAssignments)
	for _, row := range list {
		matchingRuleId, status := auditor.config.RoleAssignments.Validate(*row)

		azureResource, _ := prometheusAzure.ParseResourceId(row.Scope)

		report.Add(map[string]string{
			"resourceID":    row.ResourceID,
			"scope":         row.Scope,
			"resourceGroup": azureResource.ResourceGroup,

			"principalType":          row.PrincipalType,
			"principalObjectID":      row.PrincipalObjectID,
			"principalApplicationID": row.PrincipalApplicationID,
			"principalDisplayName":   row.PrincipalDisplayName,

			"roleDefinitionID":   row.RoleDefinitionID,
			"roleDefinitionName": row.RoleDefinitionName,

			"createdAt": row.CreationTime.Format(time.RFC3339),
			"age":       row.Age.String(),
		}, matchingRuleId, status)

		if status {
			violationMetric.AddInfo(prometheus.Labels{
				"subscriptionID":   to.String(subscription.SubscriptionID),
				"roleAssignmentID": row.RoleDefinitionID,

				"scope":         row.Scope,
				"resourceGroup": azureResource.ResourceGroup,

				"principalType":          row.PrincipalType,
				"principalObjectID":      row.PrincipalObjectID,
				"principalApplicationID": row.PrincipalApplicationID,
				"principalDisplayName":   row.PrincipalDisplayName,

				"roleDefinitionID":   row.RoleDefinitionID,
				"roleDefinitionName": row.RoleDefinitionName,
			})
		}
	}

	callback <- func() {
		auditor.logger.Infof("found %v illegal RoleAssignments", len(violationMetric.GetList()))
		violationMetric.GaugeSet(auditor.prometheus.roleAssignment)
	}
}

func (auditor *AzureAuditor) fetchRoleAssignments(ctx context.Context, subscription *subscriptions.Subscription) (list map[string]*AzureRoleAssignment) {
	list = map[string]*AzureRoleAssignment{}

	roleDefinitionList := auditor.fetchRoleDefinitionList(ctx, subscription)

	client := authorization.NewRoleAssignmentsClientWithBaseURI(auditor.azure.environment.ResourceManagerEndpoint, *subscription.SubscriptionID)
	auditor.decorateAzureClient(&client.Client, auditor.azure.authorizer)

	response, err := client.ListComplete(ctx, "", "")

	if err != nil {
		auditor.logger.Panic(err)
	}

	for response.NotDone() {
		roleAssignment := response.Value()

		roleDefinitionName := ""
		if val, exists := roleDefinitionList[to.String(roleAssignment.RoleDefinitionID)]; exists {
			roleDefinitionName = val
		}

		list[to.String(roleAssignment.Name)] = &AzureRoleAssignment{
			AzureBaseObject: &AzureBaseObject{
				ResourceID: stringPtrToStringLower(roleAssignment.ID),
			},
			Type:               stringPtrToStringLower(roleAssignment.Type),
			Scope:              stringPtrToStringLower(roleAssignment.Scope),
			PrincipalObjectID:  stringPtrToStringLower(roleAssignment.PrincipalID),
			RoleDefinitionID:   stringPtrToStringLower(roleAssignment.RoleDefinitionID),
			RoleDefinitionName: roleDefinitionName,
			Description:        to.String(roleAssignment.Description),
			CreationTime:       roleAssignment.CreatedOn.Time,
			Age:                time.Since(roleAssignment.CreatedOn.Time),
		}

		if response.NextWithContext(ctx) != nil {
			break
		}
	}

	auditor.lookupRoleAssignmentPrincipals(ctx, &list)

	return
}

func (auditor *AzureAuditor) lookupRoleAssignmentPrincipals(ctx context.Context, list *map[string]*AzureRoleAssignment) {
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

func (auditor *AzureAuditor) fetchRoleDefinitionList(ctx context.Context, subscription *subscriptions.Subscription) map[string]string {
	client := authorization.NewRoleDefinitionsClientWithBaseURI(auditor.azure.environment.ResourceManagerEndpoint, *subscription.SubscriptionID)
	auditor.decorateAzureClient(&client.Client, auditor.azure.authorizer)

	response, err := client.ListComplete(ctx, "", "")

	if err != nil {
		auditor.logger.Panic(err)
	}

	roleDefinitionList := map[string]string{}

	for response.NotDone() {
		roleDefinition := response.Value()

		roleDefinitionID := to.String(roleDefinition.ID)

		if strings.EqualFold(*roleDefinition.RoleDefinitionProperties.RoleType, "BuiltInRole") {
			// add subscription prefix to role (builtin roles don't have /subscription/xxxx-xxxx-xxxx-xxx/ prefix)
			roleDefinitionList[*subscription.ID+roleDefinitionID] = to.String(roleDefinition.RoleName)
		} else {
			roleDefinitionList[roleDefinitionID] = to.String(roleDefinition.RoleName)
		}

		if response.NextWithContext(ctx) != nil {
			break
		}
	}

	return roleDefinitionList
}

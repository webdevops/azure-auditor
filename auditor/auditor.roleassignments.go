package auditor

import (
	"context"
	"time"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/azure-sdk-for-go/services/preview/authorization/mgmt/2020-04-01-preview/authorization"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	prometheusCommon "github.com/webdevops/go-prometheus-common"
)

func (auditor *AzureAuditor) auditRoleAssignments(ctx context.Context, logger *log.Entry, subscription *subscriptions.Subscription, report *AzureAuditorReport, callback chan<- func()) {
	list := auditor.fetchRoleAssignments(ctx, logger, subscription)

	violationMetric := prometheusCommon.NewMetricsList()

	for _, object := range list {
		matchingRuleId, status := auditor.config.ResourceProviders.Validate(object)
		report.Add(object, matchingRuleId, status)

		if !status {
			violationMetric.AddInfo(prometheus.Labels{
				"subscriptionID":   to.String(subscription.SubscriptionID),
				"roleAssignmentID": object.ToPrometheusLabel("resourceID"),

				"scope":         object.ToPrometheusLabel("roleAssignment.scope"),
				"resourceGroup": object.ToPrometheusLabel("resourceGroup"),

				"principalType":          object.ToPrometheusLabel("principal.type"),
				"principalObjectID":      object.ToPrometheusLabel("principal.objectID"),
				"principalApplicationID": object.ToPrometheusLabel("principal.applicationID"),
				"principalDisplayName":   object.ToPrometheusLabel("principal.displayName"),

				"roleDefinitionID":   object.ToPrometheusLabel("role.ID"),
				"roleDefinitionName": object.ToPrometheusLabel("role.name"),
			})
		}
	}

	callback <- func() {
		logger.Infof("found %v illegal RoleAssignments", len(violationMetric.GetList()))
		violationMetric.GaugeSet(auditor.prometheus.roleAssignment)
	}
}

func (auditor *AzureAuditor) fetchRoleAssignments(ctx context.Context, logger *log.Entry, subscription *subscriptions.Subscription) (list map[string]*AzureObject) {
	list = map[string]*AzureObject{}

	roleDefinitionList := auditor.fetchRoleDefinitionList(ctx, logger, subscription)

	client := authorization.NewRoleAssignmentsClientWithBaseURI(auditor.azure.environment.ResourceManagerEndpoint, *subscription.SubscriptionID)
	auditor.decorateAzureClient(&client.Client, auditor.azure.authorizer)

	response, err := client.ListComplete(ctx, "", "")

	if err != nil {
		logger.Panic(err)
	}

	for response.NotDone() {
		roleAssignment := response.Value()

		roleDefinitionName := ""
		if val, exists := roleDefinitionList[stringPtrToStringLower(roleAssignment.RoleDefinitionID)]; exists {
			roleDefinitionName = val
		}

		list[to.String(roleAssignment.Name)] = newAzureObject(
			map[string]interface{}{
				"resourceID":        stringPtrToStringLower(roleAssignment.ID),
				"subscription.ID":   to.String(subscription.SubscriptionID),
				"subscription.name": to.String(subscription.DisplayName),

				"roleAssignment.type":        stringPtrToStringLower(roleAssignment.Type),
				"roleAssignment.description": to.String(roleAssignment.Description),
				"roleAssignment.scope":       stringPtrToStringLower(roleAssignment.Scope),

				"principal.objectID": stringPtrToStringLower(roleAssignment.PrincipalID),

				"role.ID":   stringPtrToStringLower(roleAssignment.RoleDefinitionID),
				"role.name": roleDefinitionName,

				"creationTime": roleAssignment.CreatedOn.Time,
				"age":          time.Since(roleAssignment.CreatedOn.Time),
			},
		)

		if response.NextWithContext(ctx) != nil {
			break
		}
	}

	auditor.lookupRoleAssignmentPrincipals(ctx, logger, &list)

	return
}

func (auditor *AzureAuditor) lookupRoleAssignmentPrincipals(ctx context.Context, logger *log.Entry, list *map[string]*AzureObject) {
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

func (auditor *AzureAuditor) fetchRoleDefinitionList(ctx context.Context, logger *log.Entry, subscription *subscriptions.Subscription) map[string]string {
	client := authorization.NewRoleDefinitionsClientWithBaseURI(auditor.azure.environment.ResourceManagerEndpoint, *subscription.SubscriptionID)
	auditor.decorateAzureClient(&client.Client, auditor.azure.authorizer)

	response, err := client.ListComplete(ctx, *subscription.ID, "")

	if err != nil {
		logger.Panic(err)
	}

	roleDefinitionList := map[string]string{}

	for response.NotDone() {
		roleDefinition := response.Value()

		roleDefinitionID := stringPtrToStringLower(roleDefinition.ID)
		roleDefinitionList[roleDefinitionID] = stringPtrToStringLower(roleDefinition.RoleName)

		if response.NextWithContext(ctx) != nil {
			break
		}
	}

	return roleDefinitionList
}

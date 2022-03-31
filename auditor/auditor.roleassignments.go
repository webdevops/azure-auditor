package auditor

import (
	"context"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/azure-sdk-for-go/services/preview/authorization/mgmt/2020-04-01-preview/authorization"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	prometheusCommon "github.com/webdevops/go-prometheus-common"
	prometheusAzure "github.com/webdevops/go-prometheus-common/azure"
)

func (auditor *AzureAuditor) auditRoleAssignments(ctx context.Context, logger *log.Entry, subscription *subscriptions.Subscription, report *AzureAuditorReport, callback chan<- func()) {
	list := auditor.fetchRoleAssignments(ctx, logger, subscription)

	violationMetric := prometheusCommon.NewMetricsList()

	for _, object := range list {
		matchingRuleId, status := auditor.config.RoleAssignments.Validate(object)
		report.Add(object, matchingRuleId, status)

		if !status {
			violationMetric.AddInfo(prometheus.Labels{
				"subscriptionID":   to.String(subscription.SubscriptionID),
				"roleAssignmentID": object.ToPrometheusLabel("resourceID"),

				"scope":         object.ToPrometheusLabel("roleAssignment.scope"),
				"scopeType":     object.ToPrometheusLabel("roleAssignment.scopeType"),
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

		scopeResourceId := strings.ToLower(*roleAssignment.Scope)

		scopeType := ""
		if azureInfo, err := prometheusAzure.ParseResourceId(scopeResourceId); err == nil {
			if azureInfo.ResourceName != "" {
				scopeType = "resource"
			} else if azureInfo.ResourceGroup != "" {
				scopeType = "resourcegroup"
			} else if azureInfo.Subscription != "" {
				scopeType = "subscription"
			}
		} else if strings.HasPrefix(scopeResourceId, "/providers/microsoft.management/managementgroups/") {
			scopeType = "managementgroup"
		}

		obj := newAzureObject(
			map[string]interface{}{
				"resourceID":        stringPtrToStringLower(roleAssignment.ID),
				"subscription.ID":   to.String(subscription.SubscriptionID),
				"subscription.name": to.String(subscription.DisplayName),

				"roleassignment.type":        stringPtrToStringLower(roleAssignment.Type),
				"roleassignment.description": to.String(roleAssignment.Description),
				"roleassignment.scope":       stringPtrToStringLower(roleAssignment.Scope),
				"roleassignment.scopetype":   scopeType,
				"roleassignment.createdAt":   roleAssignment.CreatedOn.Time,
				"roleassignment.age":         time.Since(roleAssignment.CreatedOn.Time),

				"principal.objectID": stringPtrToStringLower(roleAssignment.PrincipalID),

				"role.ID": stringPtrToStringLower(roleAssignment.RoleDefinitionID),
			},
		)

		if roleDefinition, exists := roleDefinitionList[stringPtrToStringLower(roleAssignment.RoleDefinitionID)]; exists {
			(*obj)["role.name"] = stringPtrToStringLower(roleDefinition.RoleName)
			(*obj)["role.type"] = stringPtrToStringLower(roleDefinition.RoleType)
		}

		list[to.String(roleAssignment.Name)] = obj

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
		(*(*list)[key])["principal.type"] = "unknown"
		if principalObjectID, ok := (*row)["principal.objectID"].(string); ok && principalObjectID != "" {
			if directoryObjectInfo, exists := principalObjectIDMap[principalObjectID]; exists && directoryObjectInfo != nil {
				(*(*list)[key])["principal.displayName"] = directoryObjectInfo.DisplayName
				(*(*list)[key])["principal.applicationID"] = directoryObjectInfo.ApplicationId
				(*(*list)[key])["principal.objectID"] = directoryObjectInfo.ObjectId
			}
		}
	}
}

func (auditor *AzureAuditor) fetchRoleDefinitionList(ctx context.Context, logger *log.Entry, subscription *subscriptions.Subscription) map[string]authorization.RoleDefinition {
	client := authorization.NewRoleDefinitionsClientWithBaseURI(auditor.azure.environment.ResourceManagerEndpoint, *subscription.SubscriptionID)
	auditor.decorateAzureClient(&client.Client, auditor.azure.authorizer)

	response, err := client.ListComplete(ctx, *subscription.ID, "")

	if err != nil {
		logger.Panic(err)
	}

	roleDefinitionList := map[string]authorization.RoleDefinition{}

	for response.NotDone() {
		roleDefinition := response.Value()

		roleDefinitionID := stringPtrToStringLower(roleDefinition.ID)
		roleDefinitionList[roleDefinitionID] = roleDefinition

		if response.NextWithContext(ctx) != nil {
			break
		}
	}

	return roleDefinitionList
}

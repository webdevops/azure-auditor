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
	azureCommon "github.com/webdevops/go-common/azure"
	prometheusCommon "github.com/webdevops/go-common/prometheus"

	"github.com/webdevops/azure-auditor/auditor/validator"
)

func (auditor *AzureAuditor) auditRoleAssignments(ctx context.Context, logger *log.Entry, subscription *subscriptions.Subscription, report *AzureAuditorReport, callback chan<- func()) {
	list := auditor.fetchRoleAssignments(ctx, logger, subscription)

	violationMetric := prometheusCommon.NewMetricsList()

	for _, object := range list {
		matchingRuleId, status := auditor.config.RoleAssignments.Validate(object)
		report.Add(object, matchingRuleId, status)

		if !status && auditor.config.RoleAssignments.IsMetricsEnabled() {
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
				"rule":               matchingRuleId,
			})
		}
	}

	callback <- func() {
		logger.Infof("found %v illegal RoleAssignments", len(violationMetric.GetList()))
		violationMetric.GaugeSet(auditor.prometheus.roleAssignment)
	}
}

func (auditor *AzureAuditor) fetchRoleAssignments(ctx context.Context, logger *log.Entry, subscription *subscriptions.Subscription) (list []*validator.AzureObject) {
	list = []*validator.AzureObject{}

	roleDefinitionList := auditor.fetchRoleDefinitionList(ctx, logger, subscription)

	client := authorization.NewRoleAssignmentsClientWithBaseURI(auditor.azure.client.Environment.ResourceManagerEndpoint, *subscription.SubscriptionID)
	auditor.decorateAzureClient(&client.Client, auditor.azure.client.Authorizer)

	response, err := client.ListComplete(ctx, "", "")

	if err != nil {
		logger.Panic(err)
	}

	for response.NotDone() {
		roleAssignment := response.Value()

		scopeResourceId := strings.ToLower(*roleAssignment.Scope)

		azureScope, _ := azureCommon.ParseResourceId(scopeResourceId)

		scopeType := ""
		if azureScope.ResourceName != "" {
			scopeType = "resource"
		} else if azureScope.ResourceGroup != "" {
			scopeType = "resourcegroup"
		} else if azureScope.Subscription != "" {
			scopeType = "subscription"
		} else if strings.HasPrefix(scopeResourceId, "/providers/microsoft.management/managementgroups/") {
			scopeType = "managementgroup"
		}

		obj := map[string]interface{}{
			"resource.ID":        stringPtrToStringLower(roleAssignment.ID),
			"subscription.ID":    to.String(subscription.SubscriptionID),
			"role.ID":            stringPtrToStringLower(roleAssignment.RoleDefinitionID),
			"principal.objectID": stringPtrToStringLower(roleAssignment.PrincipalID),
			"resourcegroup.name": azureScope.ResourceGroup,

			"roleassignment.type":        stringPtrToStringLower(roleAssignment.Type),
			"roleassignment.description": to.String(roleAssignment.Description),
			"roleassignment.scope":       stringPtrToStringLower(roleAssignment.Scope),
			"roleassignment.scopetype":   scopeType,
			"roleassignment.createdAt":   roleAssignment.CreatedOn.Time,
			"roleassignment.age":         time.Since(roleAssignment.CreatedOn.Time),
		}

		if roleDefinition, exists := roleDefinitionList[stringPtrToStringLower(roleAssignment.RoleDefinitionID)]; exists {
			obj["role.name"] = stringPtrToStringLower(roleDefinition.RoleName)
			obj["role.type"] = stringPtrToStringLower(roleDefinition.RoleType)
			obj["role.description"] = stringPtrToStringLower(roleDefinition.Description)
		}

		list = append(list, validator.NewAzureObject(obj))

		if response.NextWithContext(ctx) != nil {
			break
		}
	}

	auditor.enrichAzureObjects(ctx, subscription, &list)

	return
}

func (auditor *AzureAuditor) fetchRoleDefinitionList(ctx context.Context, logger *log.Entry, subscription *subscriptions.Subscription) map[string]authorization.RoleDefinition {
	client := authorization.NewRoleDefinitionsClientWithBaseURI(auditor.azure.client.Environment.ResourceManagerEndpoint, *subscription.SubscriptionID)
	auditor.decorateAzureClient(&client.Client, auditor.azure.client.Authorizer)

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

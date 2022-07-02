package auditor

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/Azure/go-autorest/autorest/to"
	log "github.com/sirupsen/logrus"
	azureCommon "github.com/webdevops/go-common/azure"
	prometheusCommon "github.com/webdevops/go-common/prometheus"

	"github.com/webdevops/azure-auditor/auditor/validator"
)

func (auditor *AzureAuditor) auditRoleAssignments(ctx context.Context, logger *log.Entry, subscription *armsubscriptions.Subscription, report *AzureAuditorReport, callback chan<- func()) {
	list := auditor.fetchRoleAssignments(ctx, logger, subscription)

	violationMetric := prometheusCommon.NewMetricsList()

	for _, object := range list {
		matchingRuleId, status := auditor.config.RoleAssignments.Validate(object)
		report.Add(object, matchingRuleId, status)

		if !status && auditor.config.RoleAssignments.IsMetricsEnabled() {
			violationMetric.AddInfo(
				auditor.config.RoleAssignments.CreatePrometheusMetricFromAzureObject(object, matchingRuleId),
			)
		}
	}

	callback <- func() {
		logger.Infof("found %v illegal RoleAssignments", len(violationMetric.GetList()))
		violationMetric.GaugeSetInc(auditor.prometheus.roleAssignment)
	}
}

func (auditor *AzureAuditor) fetchRoleAssignments(ctx context.Context, logger *log.Entry, subscription *armsubscriptions.Subscription) (list []*validator.AzureObject) {
	list = []*validator.AzureObject{}

	client, err := armauthorization.NewRoleAssignmentsClient(*subscription.SubscriptionID, auditor.azure.client.GetCred(), nil)
	if err != nil {
		logger.Panic(err)
	}

	pager := client.NewListPager(nil)
	for pager.More() {
		result, err := pager.NextPage(ctx)
		if err != nil {
			logger.Panic(err)
		}

		for _, roleAssignment := range result.RoleAssignmentListResult.Value {
			scopeResourceId := strings.ToLower(to.String(roleAssignment.Properties.Scope))

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
				"resource.id":        stringPtrToStringLower(roleAssignment.ID),
				"subscription.id":    to.String(subscription.SubscriptionID),
				"roledefinition.id":  stringPtrToStringLower(roleAssignment.Properties.RoleDefinitionID),
				"principal.objectid": stringPtrToStringLower(roleAssignment.Properties.PrincipalID),
				"resourcegroup.name": azureScope.ResourceGroup,

				"roleassignment.type": stringPtrToStringLower(roleAssignment.Type),
				// "roleassignment.description": to.String(roleAssignment.Properties.Description),
				"roleassignment.scope":     stringPtrToStringLower(roleAssignment.Properties.Scope),
				"roleassignment.scopetype": scopeType,
				// "roleassignment.createdon":   roleAssignment.CreatedOn.Time,
				// "roleassignment.age":         time.Since(roleAssignment.CreatedOn.Time),
			}

			list = append(list, validator.NewAzureObject(obj))

		}
	}

	auditor.enrichAzureObjects(ctx, subscription, &list)

	return
}

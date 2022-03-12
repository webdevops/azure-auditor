package auditor

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/azure-sdk-for-go/services/preview/authorization/mgmt/2020-04-01-preview/authorization"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/microsoftgraph/msgraph-sdk-go/directoryobjects/getbyids"
	"github.com/prometheus/client_golang/prometheus"
	prometheusCommon "github.com/webdevops/go-prometheus-common"
	"strings"
)

type (
	MsGraphDirectoryObjectInfo struct {
		Type          string
		DisplayName   string
		ObjectId      string
		ApplicationId string
	}
)

func (auditor *AzureAuditor) auditRoleAssignments(ctx context.Context, subscription *subscriptions.Subscription, callback chan<- func()) {
	list := auditor.fetchRoleAssignments(ctx, subscription)

	violationMetric := prometheusCommon.NewMetricsList()

	report := auditor.startReport(ReportRoleAssignments)
	for _, row := range list {
		matchingRuleId, status := auditor.config.RoleAssignments.Validate(*row)
		azureResourceInfo := extractAzureResourceInfo(row.Scope)

		report.Add(map[string]string{
			"resourceID":    row.ResourceID,
			"scope":         row.Scope,
			"resourceGroup": azureResourceInfo.ResourceGroup,

			"principalType":          row.PrincipalType,
			"principalObjectID":      row.PrincipalObjectID,
			"principalApplicationID": row.PrincipalApplicationID,
			"principalName":          row.PrincipalName,

			"roleDefinitionID":   row.RoleDefinitionID,
			"roleDefinitionName": row.RoleDefinitionName,
		}, matchingRuleId, status)

		if status {
			violationMetric.AddInfo(prometheus.Labels{
				"subscriptionID":   to.String(subscription.SubscriptionID),
				"roleAssignmentID": row.RoleDefinitionID,

				"scope":         row.Scope,
				"resourceGroup": azureResourceInfo.ResourceGroup,

				"principalType":          row.PrincipalType,
				"principalObjectID":      row.PrincipalObjectID,
				"principalApplicationID": row.PrincipalApplicationID,
				"principalName":          row.PrincipalName,

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
				ResourceID: to.String(roleAssignment.ID),
			},
			Type:               to.String(roleAssignment.Type),
			Scope:              to.String(roleAssignment.Scope),
			PrincipalObjectID:  to.String(roleAssignment.PrincipalID),
			RoleDefinitionID:   to.String(roleAssignment.RoleDefinitionID),
			RoleDefinitionName: roleDefinitionName,
			Description:        to.String(roleAssignment.Description),
		}

		if response.NextWithContext(ctx) != nil {
			break
		}
	}

	auditor.lookupRoleAssignmentPrincipals(ctx, subscription, &list)

	return
}

func (auditor *AzureAuditor) lookupRoleAssignmentPrincipals(ctx context.Context, subscription *subscriptions.Subscription, roleAssignmentList *map[string]*AzureRoleAssignment) {
	PrincipalObjectIDMap := map[string]*MsGraphDirectoryObjectInfo{}
	for _, row := range *roleAssignmentList {
		PrincipalObjectIDMap[row.PrincipalObjectID] = nil
		if val, ok := auditor.cache.Get("msgraph:" + row.PrincipalObjectID); ok {
			if directoryObjectInfo, ok := val.(*MsGraphDirectoryObjectInfo); ok {
				PrincipalObjectIDMap[row.PrincipalObjectID] = directoryObjectInfo
			}
		}
	}

	// build list of not cached entries
	lookupPrincipalObjectIDList := []string{}
	for PrincipalObjectID, directoryObjectInfo := range PrincipalObjectIDMap {
		if directoryObjectInfo == nil {
			lookupPrincipalObjectIDList = append(lookupPrincipalObjectIDList, PrincipalObjectID)
		}
	}

	// azure limits objects ids
	chunkSize := 999
	for i := 0; i < len(lookupPrincipalObjectIDList); i += chunkSize {
		end := i + chunkSize
		if end > len(lookupPrincipalObjectIDList) {
			end = len(lookupPrincipalObjectIDList)
		}

		PrincipalObjectIDChunkList := lookupPrincipalObjectIDList[i:end]

		opts := getbyids.GetByIdsRequestBuilderPostOptions{
			Body: getbyids.NewGetByIdsRequestBody(),
		}
		opts.Body.SetIds(PrincipalObjectIDChunkList)

		result, err := auditor.azure.msGraph.DirectoryObjects().GetByIds().Post(&opts)
		if err != nil {
			auditor.logger.Panic(err)
		}

		for _, row := range result.GetValue() {
			objectId := to.String(row.GetId())
			objectData := row.GetAdditionalData()

			objectType := ""
			if val, exists := objectData["@odata.type"]; exists {
				objectType = to.String(val.(*string))
				objectType = strings.ToLower(strings.TrimPrefix(objectType, "#microsoft.graph."))
			}

			displayName := ""
			if val, exists := objectData["displayName"]; exists {
				displayName = to.String(val.(*string))
			}

			applicationId := ""
			if val, exists := objectData["appId"]; exists {
				applicationId = to.String(val.(*string))
			}

			PrincipalObjectIDMap[objectId] = &MsGraphDirectoryObjectInfo{
				ObjectId:      objectId,
				ApplicationId: applicationId,
				Type:          objectType,
				DisplayName:   displayName,
			}
		}
	}

	for key, row := range *roleAssignmentList {
		if directoryObjectInfo, exists := PrincipalObjectIDMap[row.PrincipalObjectID]; exists {
			auditor.cache.Set("msgraph:"+row.PrincipalObjectID, PrincipalObjectIDMap[row.PrincipalObjectID], auditor.cacheExpiry)

			if directoryObjectInfo != nil {
				(*roleAssignmentList)[key].PrincipalType = directoryObjectInfo.Type
				(*roleAssignmentList)[key].PrincipalName = directoryObjectInfo.DisplayName
				(*roleAssignmentList)[key].PrincipalApplicationID = directoryObjectInfo.ApplicationId
			}
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

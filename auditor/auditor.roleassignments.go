package auditor

import (
	"context"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	azidentity "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/services/preview/authorization/mgmt/2020-04-01-preview/authorization"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/microsoft/kiota/abstractions/go/serialization"
	a "github.com/microsoft/kiota/authentication/go/azure"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	msgraphcore "github.com/microsoftgraph/msgraph-sdk-go-core"
	"github.com/microsoftgraph/msgraph-sdk-go/directoryobjects"
	"github.com/microsoftgraph/msgraph-sdk-go/directoryobjects/getbyids"
	"github.com/microsoftgraph/msgraph-sdk-go/models/microsoft/graph"
	"github.com/prometheus/client_golang/prometheus"
	prometheusCommon "github.com/webdevops/go-prometheus-common"
	"strings"
)

type (
	RoleAssignment struct {
		ResourceID string

		Type  string
		Scope string

		PrincipalID   string
		PrincipalType string
		PrincipalName string

		RoleDefinitionID   string
		RoleDefinitionName string

		Description string
	}
)

func (auditor *AzureAuditor) auditRoleAssignments(ctx context.Context, subscription *subscriptions.Subscription, callback chan<- func()) {
	list := auditor.fetchRoleAssignments(ctx, subscription)

	violationMetric := prometheusCommon.NewMetricsList()

	for _, row := range list {
		if !auditor.config.RoleAssignments.Validate(row) {
			scopeInfo, _ := azure.ParseResourceID(row.Scope)
			violationMetric.AddInfo(prometheus.Labels{
				"subscriptionID":   to.String(subscription.SubscriptionID),
				"roleAssignmentID": row.RoleDefinitionID,

				"scope":         row.Scope,
				"resourceGroup": scopeInfo.ResourceGroup,

				"principalType": row.PrincipalType,
				"principalID":   row.PrincipalID,
				"principalName": row.PrincipalName,

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

func (auditor *AzureAuditor) fetchRoleAssignments(ctx context.Context, subscription *subscriptions.Subscription) (list map[string]RoleAssignment) {
	list = map[string]RoleAssignment{}

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

		list[to.String(roleAssignment.Name)] = RoleAssignment{
			ResourceID:         to.String(roleAssignment.ID),
			Type:               to.String(roleAssignment.Type),
			Scope:              to.String(roleAssignment.Scope),
			PrincipalID:        to.String(roleAssignment.PrincipalID),
			RoleDefinitionID:   to.String(roleAssignment.RoleDefinitionID),
			RoleDefinitionName: roleDefinitionName,
			Description:        to.String(roleAssignment.Description),
		}

		if response.NextWithContext(ctx) != nil {
			break
		}
	}

	//	auditor.lookupRoleAssignmentPrincipals(ctx, subscription, &roleAssignmentList)

	return
}

func (auditor *AzureAuditor) lookupRoleAssignmentPrincipals(ctx context.Context, subscription *subscriptions.Subscription, roleAssignmentList *map[string]RoleAssignment) {
	cred, err := azidentity.NewEnvironmentCredential(nil)
	if err != nil {
		auditor.logger.Panic(err)
	}

	auth, err := a.NewAzureIdentityAuthenticationProvider(cred)
	if err != nil {
		auditor.logger.Panic(err)
	}

	adapter, err := msgraphsdk.NewGraphRequestAdapter(auth)
	if err != nil {
		auditor.logger.Panic(err)
	}

	client := msgraphsdk.NewGraphServiceClient(adapter)

	principalIdMap := map[string]string{}
	for _, row := range *roleAssignmentList {
		principalIdMap[row.PrincipalID] = row.PrincipalID
	}
	principalIdList := []string{}
	for _, val := range principalIdMap {
		principalIdList = append(principalIdList, val)
	}

	// azure limits objects ids
	chunkSize := 999
	for i := 0; i < len(principalIdList); i += chunkSize {
		end := i + chunkSize
		if end > len(principalIdList) {
			end = len(principalIdList)
		}

		principalIdChunkList := principalIdList[i:end]

		opts := getbyids.GetByIdsRequestBuilderPostOptions{
			Body: getbyids.NewGetByIdsRequestBody(),
		}
		opts.Body.SetIds(principalIdChunkList)

		result, err := client.DirectoryObjects().GetByIds().Post(&opts)
		if err != nil {
			auditor.logger.Panic(err)
		}

		pageIterator, err := msgraphcore.NewPageIterator(result, adapter.GraphRequestAdapterBase,
			func() serialization.Parsable {
				return directoryobjects.NewDirectoryObjectsResponse()
			})

		err = pageIterator.Iterate(func(pageItem interface{}) bool {
			directoryObject := pageItem.(graph.DirectoryObject)
			fmt.Printf("%s\n", *directoryObject.GetId())
			// Return true to continue the iteration
			return true
		})
	}

	panic("")
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

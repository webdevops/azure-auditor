package auditor

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/azure-sdk-for-go/services/preview/authorization/mgmt/2020-04-01-preview/authorization"
	"github.com/Azure/go-autorest/autorest/to"
	azureCommon "github.com/webdevops/go-common/azure"

	"github.com/webdevops/azure-auditor/auditor/validator"
)

func (auditor *AzureAuditor) enrichAzureObjects(ctx context.Context, subscription *subscriptions.Subscription, list *[]*validator.AzureObject) {
	var (
		resourceGroupList  map[string]resources.Group
		resourcesList      map[string]resources.GenericResourceExpanded
		roleDefinitionList map[string]authorization.RoleDefinition
	)
	subscriptionList := auditor.getSubscriptionList(ctx)
	if subscription != nil {
		resourceGroupList = auditor.getResourceGroupList(ctx, subscription)
		resourcesList = auditor.getResourceList(ctx, subscription)
		roleDefinitionList = auditor.getRoleDefinitionList(ctx, subscription)
	}

	inheritTag := map[string]string{}
	for _, tagName := range auditor.Opts.Azure.InheritTags {
		inheritTag[tagName] = ""
	}

	for key, row := range *list {
		obj := (*(*list)[key])

		// detect subscription info by row (if subscription is not specified before)
		if subscription == nil {
			resourceGroupList = map[string]resources.Group{}
			resourcesList = map[string]resources.GenericResourceExpanded{}
			roleDefinitionList = map[string]authorization.RoleDefinition{}

			if subscriptionID, ok := (*row)["subscription.id"].(string); ok && subscriptionID != "" {
				if val, ok := subscriptionList[subscriptionID]; ok {
					resourceGroupList = auditor.getResourceGroupList(ctx, &val)
					resourcesList = auditor.getResourceList(ctx, &val)
					roleDefinitionList = auditor.getRoleDefinitionList(ctx, &val)
				}
			}
		}

		// enrich with subscription information
		if subscriptionID, ok := (*row)["subscription.id"].(string); ok && subscriptionID != "" {
			if subscription, ok := subscriptionList[subscriptionID]; ok {
				obj["subscription.name"] = to.String(subscription.DisplayName)

				for tagName, tagValue := range subscription.Tags {
					valKey := fmt.Sprintf("subscription.tag.%v", tagName)
					obj[valKey] = to.String(tagValue)
				}
			}
		}

		// enrich with resourcegroup information
		if resourceGroupName, ok := (*row)["resourcegroup.name"].(string); ok && resourceGroupName != "" {
			resourceGroupName = strings.ToLower(resourceGroupName)
			if resourceGroup, ok := resourceGroupList[resourceGroupName]; ok {
				obj["resourcegroup.name"] = to.String(resourceGroup.Name)
				obj["resourcegroup.location"] = to.String(resourceGroup.Location)

				for tagName, tagValue := range resourceGroup.Tags {
					valKey := fmt.Sprintf("resourcegroup.tag.%v", tagName)
					tagValueStr := to.String(tagValue)
					obj[valKey] = tagValueStr

					// save tags for inheritance
					if _, ok := inheritTag[tagName]; ok {
						inheritTag[tagName] = tagValueStr
					}
				}
			}
		}

		// enrich with roledefinition information
		if val, ok := (*row)["roledefinition.id"].(string); ok && val != "" {
			if roleDefinition, ok := roleDefinitionList[val]; ok {
				obj["roledefinition.name"] = to.String(roleDefinition.RoleName)
				obj["roledefinition.type"] = to.String(roleDefinition.RoleType)
				obj["roledefinition.description"] = to.String(roleDefinition.Description)
			}
		}

		// enrich with resource information (if resource is detected)
		resourceID := ""
		if val, ok := (*row)["roleassignment.scope"].(string); ok && val != "" {
			resourceID = val
		} else if val, ok := (*row)["resource.id"].(string); ok && val != "" {
			resourceID = val
		}

		if resourceID != "" {
			if resourceInfo, err := azureCommon.ParseResourceId(resourceID); err == nil && resourceInfo.ResourceName != "" {
				resourceID := strings.ToLower(resourceInfo.ResourceId())
				obj["resource.name"] = resourceInfo.ResourceName
				obj["resource.type"] = resourceInfo.ResourceType

				if resourceInfo.ResourceSubPath != "" {
					obj["resource.extension.path"] = resourceInfo.ResourceSubPath
					subPathInfo := strings.SplitN(strings.Trim(resourceInfo.ResourceSubPath, "/"), "/", 2)
					if len(subPathInfo) >= 2 {
						obj["resource.extension.type"] = subPathInfo[0]
						obj["resource.extension.name"] = subPathInfo[1]
					}
				}

				if resource, ok := resourcesList[resourceID]; ok {
					obj["resource.location"] = to.String(resource.Location)

					// use tags from inhertiance for (as default)
					for tagName, tagValue := range inheritTag {
						valKey := fmt.Sprintf("resource.tag.%v", tagName)
						obj[valKey] = tagValue
					}

					// resource tags (might overwrite inhertiance tags)
					for tagName, tagValue := range resource.Tags {
						valKey := fmt.Sprintf("resource.tag.%v", tagName)
						obj[valKey] = to.String(tagValue)
					}
				}
			}
		}

	}

	// enrich with principal information
	auditor.enrichAzureObjectsWithMsGraphPrincipals(ctx, list)
}

func (auditor *AzureAuditor) enrichAzureObjectsWithMsGraphPrincipals(ctx context.Context, list *[]*validator.AzureObject) {
	principalObjectIDMap := map[string]*MsGraphDirectoryObjectInfo{}
	for _, row := range *list {
		if principalObjectID, ok := (*row)["principal.objectid"].(string); ok && principalObjectID != "" {
			principalObjectIDMap[principalObjectID] = nil
		}
	}

	if len(principalObjectIDMap) > 0 {
		auditor.lookupPrincipalIdMap(ctx, &principalObjectIDMap)

		for key, row := range *list {
			obj := (*(*list)[key])

			obj["principal.type"] = "unknown"
			if principalObjectID, ok := (*row)["principal.objectid"].(string); ok && principalObjectID != "" {
				if directoryObjectInfo, exists := principalObjectIDMap[principalObjectID]; exists && directoryObjectInfo != nil {

					obj["principal.objectid"] = directoryObjectInfo.ObjectId
					obj["principal.type"] = directoryObjectInfo.Type

					if directoryObjectInfo.DisplayName != "" {
						obj["principal.displayname"] = directoryObjectInfo.DisplayName
					}

					if directoryObjectInfo.ApplicationId != "" {
						obj["principal.applicationid"] = directoryObjectInfo.ApplicationId
					}

					if directoryObjectInfo.ServicePrincipalType != "" {
						obj["principal.serviceprincipaltype"] = directoryObjectInfo.ServicePrincipalType
					}

					if directoryObjectInfo.ManagedIdentity != "" {
						obj["principal.managedidentity"] = directoryObjectInfo.ManagedIdentity
					}
				}
			}
		}
	}
}

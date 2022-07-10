package auditor

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/Azure/go-autorest/autorest/to"

	azureCommon "github.com/webdevops/go-common/azuresdk/armclient"

	"github.com/webdevops/azure-auditor/auditor/validator"
)

func (auditor *AzureAuditor) enrichAzureObjects(ctx context.Context, subscription *armsubscriptions.Subscription, list *[]*validator.AzureObject) {
	if subscription != nil {
		// fixed subscription
		auditor.enrichAzureObjectsWithSubscription(ctx, subscription, list)
	} else {
		// list all subscriptions
		subscriptionIdList := map[string]string{}
		for _, row := range *list {
			if subscriptionID, ok := (*row)["subscription.id"].(string); ok && subscriptionID != "" {
				subscriptionIdList[subscriptionID] = subscriptionID
			}
		}

		subscriptionList := auditor.getSubscriptionList(ctx)
		for _, subscriptionId := range subscriptionIdList {
			if subscription, ok := subscriptionList[subscriptionId]; ok {
				auditor.enrichAzureObjectsWithSubscription(ctx, subscription, list)
			}
		}
	}

	// enrich with principal information
	auditor.enrichAzureObjectsWithMsGraphPrincipals(ctx, list)
}

func (auditor *AzureAuditor) enrichAzureObjectsWithSubscription(ctx context.Context, subscription *armsubscriptions.Subscription, list *[]*validator.AzureObject) {
	resourceGroupList := auditor.getResourceGroupList(ctx, subscription)
	resourcesList := auditor.getResourceList(ctx, subscription)
	roleDefinitionList := auditor.getRoleDefinitionList(ctx, subscription)

	for key, row := range *list {
		obj := (*(*list)[key])

		if subscriptionID, ok := obj["subscription.id"].(string); ok && subscriptionID != "" && subscriptionID == *subscription.SubscriptionID {
			// init inherit tags
			inheritTag := map[string]string{}
			for _, tagName := range auditor.Opts.Azure.InheritTags {
				inheritTag[tagName] = ""
			}

			// enrich with subscription information
			obj["subscription.name"] = to.String(subscription.DisplayName)
			for tagName, tagValue := range subscription.Tags {
				valKey := fmt.Sprintf("subscription.tag.%v", tagName)
				obj[valKey] = to.String(tagValue)
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
			if roleDefinitionId, ok := (*row)["roledefinition.id"].(string); ok && roleDefinitionId != "" {
				roleDefinitionId = strings.ToLower(roleDefinitionId)
				if roleDefinition, ok := roleDefinitionList[strings.ToLower(roleDefinitionId)]; ok {
					obj["roledefinition.name"] = to.String(roleDefinition.Properties.RoleName)
					obj["roledefinition.type"] = to.String(roleDefinition.Properties.RoleType)
					obj["roledefinition.description"] = to.String(roleDefinition.Properties.Description)
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
	}
}

func (auditor *AzureAuditor) enrichAzureObjectsWithMsGraphPrincipals(ctx context.Context, list *[]*validator.AzureObject) {
	principalObjectIdMap := map[string]string{}
	// create uniq pricipalid list
	for _, row := range *list {
		if principalId, ok := (*row)["principal.objectid"].(string); ok && principalId != "" {
			principalObjectIdMap[principalId] = principalId
		}
	}

	// create pricipalid list
	principalIdList := []string{}
	for _, principalId := range principalObjectIdMap {
		principalIdList = append(principalIdList, principalId)
	}

	if len(principalIdList) > 0 {
		principalObjectMap, err := auditor.azure.msGraph.LookupPrincipalID(principalIdList...)
		if err != nil {
			auditor.logger.Panic(err)
		}

		for key, row := range *list {
			obj := (*(*list)[key])

			obj["principal.type"] = "unknown"
			if principalObjectID, ok := (*row)["principal.objectid"].(string); ok && principalObjectID != "" {
				if directoryObjectInfo, exists := principalObjectMap[principalObjectID]; exists && directoryObjectInfo != nil {

					obj["principal.objectid"] = directoryObjectInfo.ObjectID
					obj["principal.type"] = directoryObjectInfo.Type

					if directoryObjectInfo.DisplayName != "" {
						obj["principal.displayname"] = directoryObjectInfo.DisplayName
					}

					if directoryObjectInfo.ApplicationID != "" {
						obj["principal.applicationid"] = directoryObjectInfo.ApplicationID
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

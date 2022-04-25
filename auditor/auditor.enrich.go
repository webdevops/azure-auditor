package auditor

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/go-autorest/autorest/to"

	"github.com/webdevops/azure-auditor/auditor/validator"
)

func (auditor *AzureAuditor) enrichAzureObjects(ctx context.Context, subscription *subscriptions.Subscription, list *[]*validator.AzureObject) {
	subscriptionList := auditor.getSubscriptionList(ctx)
	resourceGroupList := auditor.getResourceGroupList(ctx, subscription)
	resourcesList := auditor.getResourceList(ctx, subscription)

	for key, row := range *list {
		obj := (*(*list)[key])

		// enrich with subscription information
		if subscriptionID, ok := (*row)["subscription.ID"].(string); ok && subscriptionID != "" {
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
			if resourceGroup, ok := resourceGroupList[resourceGroupName]; ok {
				obj["resourcegroup.name"] = to.String(resourceGroup.Name)
				obj["resourcegroup.location"] = to.String(resourceGroup.Location)

				for tagName, tagValue := range resourceGroup.Tags {
					valKey := fmt.Sprintf("resourcegroup.tag.%v", tagName)
					obj[valKey] = to.String(tagValue)
				}
			}
		}

		// enrich with resource information
		if resourceID, ok := (*row)["resource.ID"].(string); ok && resourceID != "" {
			resourceID := strings.ToLower(resourceID)
			if resource, ok := resourcesList[resourceID]; ok {
				obj["resource.type"] = to.String(resource.Type)
				obj["resource.location"] = to.String(resource.Location)

				for tagName, tagValue := range resource.Tags {
					valKey := fmt.Sprintf("resource.tag.%v", tagName)
					obj[valKey] = to.String(tagValue)
				}
			}
		}

		// enrich with resource information
		if resourceID, ok := (*row)["roleassignment.scope"].(string); ok && resourceID != "" {
			resourceID := strings.ToLower(resourceID)
			if resource, ok := resourcesList[resourceID]; ok {
				obj["resource.type"] = to.String(resource.Type)
				obj["resource.location"] = to.String(resource.Location)

				for tagName, tagValue := range resource.Tags {
					valKey := fmt.Sprintf("resource.tag.%v", tagName)
					obj[valKey] = to.String(tagValue)
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
		if principalObjectID, ok := (*row)["principal.objectID"].(string); ok && principalObjectID != "" {
			principalObjectIDMap[principalObjectID] = nil
		}
	}

	if len(principalObjectIDMap) > 0 {
		auditor.lookupPrincipalIdMap(ctx, &principalObjectIDMap)

		for key, row := range *list {
			(*(*list)[key])["principal.type"] = "unknown"
			if principalObjectID, ok := (*row)["principal.objectID"].(string); ok && principalObjectID != "" {
				if directoryObjectInfo, exists := principalObjectIDMap[principalObjectID]; exists && directoryObjectInfo != nil {
					(*list)[key] = directoryObjectInfo.AddToAzureObject((*list)[key])
				}
			}
		}
	}
}

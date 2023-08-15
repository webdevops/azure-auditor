package auditor

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"

	"github.com/Azure/go-autorest/autorest/to"
)

func (auditor *AzureAuditor) getSubscriptionList(ctx context.Context) (list map[string]*armsubscriptions.Subscription) {
	list, err := auditor.azure.client.ListCachedSubscriptions(ctx)
	if err != nil {
		auditor.Logger.Panic(err)
	}
	return list
}

func (auditor *AzureAuditor) getResourceGroupList(ctx context.Context, subscription *armsubscriptions.Subscription) (list map[string]*armresources.ResourceGroup) {
	list, err := auditor.azure.client.ListCachedResourceGroups(ctx, *subscription.SubscriptionID)
	if err != nil {
		auditor.Logger.Panic(err)
	}
	return list
}

func (auditor *AzureAuditor) getResourceList(ctx context.Context, subscription *armsubscriptions.Subscription) (list map[string]*armresources.GenericResourceExpanded) {
	auditor.locks.resources.Lock()
	defer auditor.locks.resources.Unlock()

	list = map[string]*armresources.GenericResourceExpanded{}

	cacheKey := "resources:" + *subscription.SubscriptionID
	if val, ok := auditor.cache.Get(cacheKey); ok {
		// fetched from cache
		list = val.(map[string]*armresources.GenericResourceExpanded)
		return
	}

	client, err := armresources.NewClient(*subscription.SubscriptionID, auditor.azure.client.GetCred(), nil)
	if err != nil {
		auditor.Logger.Panic(err)
	}
	pager := client.NewListPager(nil)

	for pager.More() {
		result, err := pager.NextPage(ctx)
		if err != nil {
			auditor.Logger.Panic(err)
		}

		for _, item := range result.ResourceListResult.Value {
			resourceID := strings.ToLower(to.String(item.ID))
			list[resourceID] = item
		}
	}

	auditor.Logger.Infof("found %v Azure Resoures for Subscription %v (%v) (cache update)", len(list), to.String(subscription.DisplayName), to.String(subscription.SubscriptionID))

	// save to cache
	_ = auditor.cache.Add(cacheKey, list, auditor.cacheExpiry)

	return
}

func (auditor *AzureAuditor) getRoleDefinitionList(ctx context.Context, subscription *armsubscriptions.Subscription) (list map[string]*armauthorization.RoleDefinition) {
	auditor.locks.resources.Lock()
	defer auditor.locks.resources.Unlock()

	list = map[string]*armauthorization.RoleDefinition{}

	cacheKey := "roledefinitions:" + *subscription.SubscriptionID
	if val, ok := auditor.cache.Get(cacheKey); ok {
		// fetched from cache
		list = val.(map[string]*armauthorization.RoleDefinition)
		return
	}

	client, err := armauthorization.NewRoleDefinitionsClient(auditor.azure.client.GetCred(), nil)
	if err != nil {
		auditor.Logger.Panic(err)
	}

	pager := client.NewListPager(*subscription.ID, nil)
	for pager.More() {
		result, err := pager.NextPage(ctx)
		if err != nil {
			auditor.Logger.Panic(err)
		}

		for _, item := range result.RoleDefinitionListResult.Value {
			resourceID := strings.ToLower(to.String(item.ID))
			list[resourceID] = item
		}
	}

	auditor.Logger.Infof("found %v Azure RoleDefinitions for Subscription %v (%v) (cache update)", len(list), to.String(subscription.DisplayName), to.String(subscription.SubscriptionID))

	// save to cache
	_ = auditor.cache.Add(cacheKey, list, auditor.cacheExpiry)

	return
}

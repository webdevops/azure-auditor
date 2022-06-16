package auditor

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/azure-sdk-for-go/services/preview/authorization/mgmt/2020-04-01-preview/authorization"
	"github.com/Azure/go-autorest/autorest/to"
)

func (auditor *AzureAuditor) getSubscriptionList(ctx context.Context) (list map[string]subscriptions.Subscription) {
	auditor.locks.subscriptions.Lock()
	defer auditor.locks.subscriptions.Unlock()

	if val, ok := auditor.cache.Get("subscriptions"); ok {
		// fetched from cache
		list = val.(map[string]subscriptions.Subscription)
		return
	}

	list, err := auditor.azure.client.ListSubscriptions(ctx)
	if err != nil {
		auditor.logger.Panic(err)
	}

	auditor.logger.Infof("found %v Azure Subscriptions (cache update)", len(list))

	// save to cache
	_ = auditor.cache.Add("subscriptions", list, auditor.cacheExpiry)

	return
}

func (auditor *AzureAuditor) getResourceGroupList(ctx context.Context, subscription *subscriptions.Subscription) (list map[string]resources.Group) {
	auditor.locks.resourceGroups.Lock()
	defer auditor.locks.resourceGroups.Unlock()

	list = map[string]resources.Group{}

	cacheKey := "resourcegroups:" + *subscription.SubscriptionID
	if val, ok := auditor.cache.Get(cacheKey); ok {
		// fetched from cache
		list = val.(map[string]resources.Group)
		return
	}

	client := resources.NewGroupsClientWithBaseURI(auditor.azure.client.Environment.ResourceManagerEndpoint, *subscription.SubscriptionID)
	auditor.decorateAzureClient(&client.Client, auditor.azure.client.GetAuthorizer())

	listResult, err := client.ListComplete(ctx, "", nil)
	if err != nil {
		auditor.logger.Panic(err)
	}

	for _, item := range *listResult.Response().Value {
		resourceGroupName := strings.ToLower(to.String(item.Name))
		list[resourceGroupName] = item
	}

	auditor.logger.Infof("found %v Azure ResourceGroups for Subscription %v (%v) (cache update)", len(list), to.String(subscription.DisplayName), to.String(subscription.SubscriptionID))

	// save to cache
	_ = auditor.cache.Add(cacheKey, list, auditor.cacheExpiry)

	return
}

func (auditor *AzureAuditor) getResourceList(ctx context.Context, subscription *subscriptions.Subscription) (list map[string]resources.GenericResourceExpanded) {
	auditor.locks.resources.Lock()
	defer auditor.locks.resources.Unlock()

	list = map[string]resources.GenericResourceExpanded{}

	cacheKey := "resources:" + *subscription.SubscriptionID
	if val, ok := auditor.cache.Get(cacheKey); ok {
		// fetched from cache
		list = val.(map[string]resources.GenericResourceExpanded)
		return
	}

	client := resources.NewClientWithBaseURI(auditor.azure.client.Environment.ResourceManagerEndpoint, *subscription.SubscriptionID)
	auditor.decorateAzureClient(&client.Client, auditor.azure.client.GetAuthorizer())

	listResult, err := client.ListComplete(ctx, "", "", nil)
	if err != nil {
		auditor.logger.Panic(err)
	}

	for _, item := range *listResult.Response().Value {
		resourceID := strings.ToLower(to.String(item.ID))
		list[resourceID] = item
	}

	auditor.logger.Infof("found %v Azure Resoures for Subscription %v (%v) (cache update)", len(list), to.String(subscription.DisplayName), to.String(subscription.SubscriptionID))

	// save to cache
	_ = auditor.cache.Add(cacheKey, list, auditor.cacheExpiry)

	return
}

func (auditor *AzureAuditor) getRoleDefinitionList(ctx context.Context, subscription *subscriptions.Subscription) (list map[string]authorization.RoleDefinition) {
	auditor.locks.resources.Lock()
	defer auditor.locks.resources.Unlock()

	list = map[string]authorization.RoleDefinition{}

	cacheKey := "roledefinitions:" + *subscription.SubscriptionID
	if val, ok := auditor.cache.Get(cacheKey); ok {
		// fetched from cache
		list = val.(map[string]authorization.RoleDefinition)
		return
	}

	client := authorization.NewRoleDefinitionsClientWithBaseURI(auditor.azure.client.Environment.ResourceManagerEndpoint, *subscription.SubscriptionID)
	auditor.decorateAzureClient(&client.Client, auditor.azure.client.GetAuthorizer())

	listResult, err := client.ListComplete(ctx, *subscription.ID, "")
	if err != nil {
		auditor.logger.Panic(err)
	}

	for _, item := range *listResult.Response().Value {
		resourceID := strings.ToLower(to.String(item.ID))
		list[resourceID] = item
	}

	auditor.logger.Infof("found %v Azure RoleDefinitions for Subscription %v (%v) (cache update)", len(list), to.String(subscription.DisplayName), to.String(subscription.SubscriptionID))

	// save to cache
	_ = auditor.cache.Add(cacheKey, list, auditor.cacheExpiry)

	return
}

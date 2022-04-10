package auditor

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/go-autorest/autorest/to"
)

func (auditor *AzureAuditor) getSubscriptionList(ctx context.Context) (list []subscriptions.Subscription) {
	auditor.locks.subscriptions.Lock()
	defer auditor.locks.subscriptions.Unlock()

	list = []subscriptions.Subscription{}

	if val, ok := auditor.cache.Get("subscriptions"); ok {
		// fetched from cache
		list = val.([]subscriptions.Subscription)
		return
	}

	client := subscriptions.NewClientWithBaseURI(auditor.azure.client.Environment.ResourceManagerEndpoint)
	auditor.decorateAzureClient(&client.Client, auditor.azure.client.Authorizer)

	if len(auditor.Opts.Azure.Subscription) == 0 {
		listResult, err := client.List(ctx)
		if err != nil {
			auditor.logger.Panic(err)
		}
		list = listResult.Values()
	} else {
		for _, subId := range auditor.Opts.Azure.Subscription {
			result, err := client.Get(ctx, subId)
			if err != nil {
				auditor.logger.Panic(err)
			}
			list = append(list, result)
		}
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
	auditor.decorateAzureClient(&client.Client, auditor.azure.client.Authorizer)

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

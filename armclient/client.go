package armclient

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/Azure/go-autorest/autorest/to"
	cache "github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
)

type (
	Client struct {
		cloud cloud.Configuration

		logger *log.Logger

		cache    *cache.Cache
		cacheTtl time.Duration

		subscriptionFilter []string

		cacheAuthorizerTtl time.Duration

		userAgent string
	}
)

// Creates new Azure SDK ARM client
func NewClient(cloudConfig cloud.Configuration, logger *log.Logger) *Client {
	azureClient := &Client{}
	azureClient.cloud = cloudConfig

	azureClient.cacheTtl = 30 * time.Minute
	azureClient.cache = cache.New(60*time.Minute, 60*time.Second)

	azureClient.cacheAuthorizerTtl = 15 * time.Minute

	azureClient.logger = logger

	return azureClient
}

// Creates new Azure SDK ARM client with environment name as string
func NewClientWithCloudName(cloudName string, logger *log.Logger) (*Client, error) {
	var cloudConfig cloud.Configuration

	switch strings.ToLower(cloudName) {
	case "azurepublic", "azurepubliccloud":
		cloudConfig = cloud.AzurePublic
	case "azurechina", "azurechinacloud":
		cloudConfig = cloud.AzurePublic
	case "azuregovernment", "azuregovernmentcloud", "azureusgovernmentcloud":
		cloudConfig = cloud.AzureGovernment
	default:
		return nil, fmt.Errorf(`unable to set Azure Cloud "%v", not valid`, cloudName)
	}

	return NewClient(cloudConfig, logger), nil
}

// returns Azure ARM credential
func (azureClient *Client) GetCred() azcore.TokenCredential {
	cacheKey := "authorizer"
	if v, ok := azureClient.cache.Get(cacheKey); ok {
		if cred, ok := v.(azcore.TokenCredential); ok {
			return cred
		}
	}

	cred, err := azureClient.createAuthorizer()
	if err != nil {
		panic(err)
	}

	azureClient.cache.Set(cacheKey, cred, azureClient.cacheAuthorizerTtl)

	return cred
}

// creates new azure credential authorizer based on azure environment
func (azureClient *Client) createAuthorizer() (azcore.TokenCredential, error) {
	// azure authorizer
	switch strings.ToLower(os.Getenv("AZURE_AUTH")) {
	case "az", "cli", "azcli":
		// azurecli authentication
		opts := azidentity.AzureCLICredentialOptions{}
		return azidentity.NewAzureCLICredential(&opts)
	default:
		// general azure authentication (env vars, service principal, msi, ...)
		opts := azidentity.DefaultAzureCredentialOptions{
			ClientOptions: azcore.ClientOptions{
				Cloud: azureClient.cloud,
			},
		}
		return azidentity.NewDefaultAzureCredential(&opts)
	}
}

// Returns selected Azure cloud/environment configuration
func (azureClient *Client) GetCloud() cloud.Configuration {
	return azureClient.cloud
}

// Set user agent for all API calls
func (azureClient *Client) SetUserAgent(useragent string) {
	azureClient.userAgent = useragent
}

// Set TTL for service discovery cache
func (azureClient *Client) SetCacheTtl(ttl time.Duration) {
	azureClient.cacheTtl = ttl
}

// Set subscription filter, other subscriptions will be ignored
func (azureClient *Client) SetSubscriptionFilter(subscriptionId ...string) {
	azureClient.subscriptionFilter = subscriptionId
}

// Return list of subscription with filter by subscription ids
func (azureClient *Client) ListCachedSubscriptionsWithFilter(ctx context.Context, subscriptionFilter ...string) (map[string]*armsubscriptions.Subscription, error) {
	availableSubscriptions, err := azureClient.ListCachedSubscriptions(ctx)
	if err != nil {
		return nil, err
	}

	// filter subscriptions
	if len(subscriptionFilter) > 0 {
		var tmp map[string]*armsubscriptions.Subscription
		for _, subscription := range availableSubscriptions {
			for _, subscriptionID := range subscriptionFilter {
				if strings.EqualFold(subscriptionID, to.String(subscription.SubscriptionID)) {
					tmp[*subscription.SubscriptionID] = subscription
				}
			}
		}

		availableSubscriptions = tmp
	}

	return availableSubscriptions, nil
}

// Return cached list of Azure Subscriptions as map (key is subscription id)
func (azureClient *Client) ListCachedSubscriptions(ctx context.Context) (map[string]*armsubscriptions.Subscription, error) {
	cacheKey := "subscriptions"
	if v, ok := azureClient.cache.Get(cacheKey); ok {
		if cacheData, ok := v.(map[string]*armsubscriptions.Subscription); ok {
			return cacheData, nil
		}
	}

	azureClient.logger.Debug("updating cached Azure Subscription list")
	list, err := azureClient.ListSubscriptions(ctx)
	if err != nil {
		return nil, err
	}
	azureClient.logger.Debugf("found %v Azure Subscriptions", len(list))

	azureClient.cache.Set(cacheKey, list, azureClient.cacheTtl)

	return list, nil
}

// Return list of Azure Subscriptions as map (key is subscription id)
func (azureClient *Client) ListSubscriptions(ctx context.Context) (map[string]*armsubscriptions.Subscription, error) {
	list := map[string]*armsubscriptions.Subscription{}

	client, err := armsubscriptions.NewClient(azureClient.GetCred(), nil)
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(nil)
	for pager.More() {
		result, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, subscription := range result.SubscriptionListResult.Value {
			if len(azureClient.subscriptionFilter) > 0 {
				// use subscription filter
				for _, subscriptionId := range azureClient.subscriptionFilter {
					if strings.EqualFold(*subscription.SubscriptionID, subscriptionId) {
						list[*subscription.SubscriptionID] = subscription
						break
					}
				}
			} else {
				list[*subscription.SubscriptionID] = subscription
			}
		}
	}

	return list, nil
}

// Return cached list of Azure ResourceGroups as map (key is name of ResourceGroup)
func (azureClient *Client) ListCachedResourceGroups(ctx context.Context, subscription string) (map[string]*armresources.ResourceGroup, error) {
	list := map[string]*armresources.ResourceGroup{}

	cacheKey := "resourcegroups:" + subscription
	if v, ok := azureClient.cache.Get(cacheKey); ok {
		if cacheData, ok := v.(map[string]*armresources.ResourceGroup); ok {
			return cacheData, nil
		}
	}

	azureClient.logger.WithField("subscriptionID", subscription).Debug("updating cached Azure ResourceGroup list")
	list, err := azureClient.ListResourceGroups(ctx, subscription)
	if err != nil {
		return list, err
	}
	azureClient.logger.WithField("subscriptionID", subscription).Debugf("found %v Azure ResourceGroups", len(list))

	azureClient.cache.Set(cacheKey, list, azureClient.cacheTtl)

	return list, nil
}

// Return list of Azure ResourceGroups as map (key is name of ResourceGroup)
func (azureClient *Client) ListResourceGroups(ctx context.Context, subscription string) (map[string]*armresources.ResourceGroup, error) {
	list := map[string]*armresources.ResourceGroup{}

	client, err := armresources.NewResourceGroupsClient(subscription, azureClient.GetCred(), nil)
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(nil)
	for pager.More() {
		result, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if result.ResourceGroupListResult.Value != nil {
			for _, resourceGroup := range result.ResourceGroupListResult.Value {
				rgName := strings.ToLower(to.String(resourceGroup.Name))
				list[rgName] = resourceGroup
			}
		}
	}

	return list, nil
}

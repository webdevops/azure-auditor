package azure

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/to"
	cache "github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"

	"github.com/webdevops/go-common/prometheus/azuretracing"
)

type (
	Client struct {
		Environment azure.Environment

		logger *log.Logger

		cache    *cache.Cache
		cacheTtl time.Duration

		subscriptionFilter []string

		cacheAuthorizerTtl time.Duration

		userAgent string
	}
)

func NewClient(environment azure.Environment, logger *log.Logger) *Client {
	azureClient := &Client{}
	azureClient.Environment = environment

	azureClient.cacheTtl = 30 * time.Minute
	azureClient.cache = cache.New(60*time.Minute, 60*time.Second)

	azureClient.cacheAuthorizerTtl = 15 * time.Minute

	azureClient.logger = logger

	return azureClient
}

func NewClientFromEnvironment(environmentName string, logger *log.Logger) (*Client, error) {
	environment, err := azure.EnvironmentFromName(environmentName)
	if err != nil {
		return nil, err
	}

	return NewClient(environment, logger), nil
}

func (azureClient *Client) GetCred() azcore.TokenCredential {
	cacheKey := "authorizer"
	if v, ok := azureClient.cache.Get(cacheKey); ok {
		if authorizer, ok := v.(azcore.TokenCredential); ok {
			return authorizer
		}
	}

	authorizer, err := azureClient.createAuthorizer()
	if err != nil {
		panic(err)
	}

	azureClient.cache.Set(cacheKey, authorizer, azureClient.cacheAuthorizerTtl)

	return authorizer
}

func (azureClient *Client) createAuthorizer() (azcore.TokenCredential, error) {
	environment := cloud.AzurePublic
	if val := os.Getenv("AZURE_ENVIRONMENT"); val != "" {
		switch strings.ToLower(val) {
		case "azurepublic", "azurepubliccloud":
			environment = cloud.AzurePublic
		case "azurechina", "azurechinacloud":
			environment = cloud.AzurePublic
		case "azuregovernment", "azuregovernmentcloud":
			environment = cloud.AzureGovernment
		}
	}

	// azure authorizer
	switch strings.ToLower(os.Getenv("AZURE_AUTH")) {
	case "az", "cli", "azcli":
		opts := azidentity.AzureCLICredentialOptions{}
		return azidentity.NewAzureCLICredential(&opts)
	default:
		opts := azidentity.DefaultAzureCredentialOptions{
			ClientOptions: azcore.ClientOptions{
				Cloud: environment,
			},
		}
		return azidentity.NewDefaultAzureCredential(&opts)
	}
}

func (azureClient *Client) GetEnvironment() azure.Environment {
	return azureClient.Environment
}

func (azureClient *Client) SetUserAgent(useragent string) {
	azureClient.userAgent = useragent
}

func (azureClient *Client) SetCacheTtl(ttl time.Duration) {
	azureClient.cacheTtl = ttl
}

func (azureClient *Client) SetSubscriptionFilter(subscriptionId ...string) {
	azureClient.subscriptionFilter = subscriptionId
}

func (azureClient *Client) DecorateAzureAutorest(client *autorest.Client) {
	//	azureClient.DecorateAzureAutorestWithAuthorizer(client, azureClient.GetCred())
}

func (azureClient *Client) DecorateAzureAutorestWithAuthorizer(client *autorest.Client, authorizer autorest.Authorizer) {
	client.Authorizer = authorizer
	if azureClient.userAgent != "" {
		if err := client.AddToUserAgent(azureClient.userAgent); err != nil {
			panic(err)
		}
	}

	azuretracing.DecorateAzureAutoRestClient(client)
}

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

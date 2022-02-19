package auditor

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	log "github.com/sirupsen/logrus"
	"github.com/webdevops/azure-audit-exporter/config"
	"github.com/webdevops/go-prometheus-common/azuretracing"
	"time"
)

type (
	AzureAuditor struct {
		UserAgent string
		Opts      config.Opts

		logger *log.Entry

		azure struct {
			authorizer    autorest.Authorizer
			environment   azure.Environment
			subscriptions []subscriptions.Subscription
		}
	}
)

func NewAzureAuditor() *AzureAuditor {
	auditor := AzureAuditor{}
	auditor.logger = log.WithFields(log.Fields{})
	return &auditor
}

func (auditor *AzureAuditor) Init() {
	auditor.initAzure()
}

func (auditor *AzureAuditor) Run(scrapeTime time.Duration) {
	auditor.Init()

	go func() {
		for {
			auditor.updateAzureSubscriptions()

			time.Sleep(scrapeTime)
		}
	}()
}

func (auditor *AzureAuditor) initAzure() {
	var err error

	// azure authorizer
	auditor.azure.authorizer, err = auth.NewAuthorizerFromEnvironment()
	if err != nil {
		auditor.logger.Panic(err)
	}

	auditor.azure.environment, err = azure.EnvironmentFromName(*auditor.Opts.Azure.Environment)
	if err != nil {
		auditor.logger.Panic(err)
	}
}

func (auditor *AzureAuditor) updateAzureSubscriptions() {
	ctx := context.Background()

	client := subscriptions.NewClientWithBaseURI(auditor.azure.environment.ResourceManagerEndpoint)
	auditor.decorateAzureClient(&client.Client, auditor.azure.authorizer)

	if len(auditor.Opts.Azure.Subscription) == 0 {
		listResult, err := client.List(ctx)
		if err != nil {
			auditor.logger.Panic(err)
		}
		auditor.azure.subscriptions = listResult.Values()
	} else {
		auditor.azure.subscriptions = []subscriptions.Subscription{}
		for _, subId := range auditor.Opts.Azure.Subscription {
			result, err := client.Get(ctx, subId)
			if err != nil {
				auditor.logger.Panic(err)
			}
			auditor.azure.subscriptions = append(auditor.azure.subscriptions, result)
		}
	}
}

func (auditor *AzureAuditor) decorateAzureClient(client *autorest.Client, authorizer autorest.Authorizer) {
	client.Authorizer = authorizer
	if err := client.AddToUserAgent(auditor.UserAgent); err != nil {
		auditor.logger.Panic(err)
	}

	azuretracing.DecorateAzureAutoRestClient(client)
}

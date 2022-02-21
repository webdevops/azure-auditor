package auditor

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/patrickmn/go-cache"
	cron "github.com/robfig/cron/v3"
	log "github.com/sirupsen/logrus"
	"github.com/webdevops/azure-audit-exporter/config"
	"github.com/webdevops/go-prometheus-common/azuretracing"
	"sync"
	"time"
)

type (
	AzureAuditor struct {
		UserAgent string
		Opts      config.Opts

		logger *log.Entry

		config AuditConfig

		azure struct {
			authorizer  autorest.Authorizer
			environment azure.Environment
		}

		locks struct {
			subscriptions sync.Mutex
		}

		cron *cron.Cron

		cache       *cache.Cache
		cacheExpiry time.Duration

		prometheus auditorPrometheus
	}
)

func NewAzureAuditor() *AzureAuditor {
	auditor := AzureAuditor{}
	auditor.logger = log.WithFields(log.Fields{})
	return &auditor
}

func (auditor *AzureAuditor) Init() {
	auditor.initAzure()
	auditor.initPrometheus()
	auditor.initCache()
	auditor.initCron()
}

func (auditor *AzureAuditor) GetConfig() AuditConfig {
	return auditor.config
}

func (auditor *AzureAuditor) Run() {
	auditor.Init()

	// force subscription list update
	auditor.getSubscriptionList(context.Background())

	if auditor.config.ResourceGroups.IsEnabled() {
		auditor.addCronjob(
			"ResourceGroups",
			auditor.Opts.Cronjobs.ResourceGroups,
			auditor.auditResourceGroups,
			func() {
				auditor.prometheus.resourceGroup.Reset()
			},
		)
	}

	if auditor.config.RoleAssignments.IsEnabled() {
		auditor.addCronjob(
			"RoleAssignments",
			auditor.Opts.Cronjobs.RoleAssignments,
			auditor.auditRoleAssignments,
			func() {
				auditor.prometheus.roleAssignment.Reset()
			},
		)
	}

	if auditor.config.KeyvaultAccessPolicies.IsEnabled() {
		auditor.addCronjob(
			"Keyvault AccessPolicies",
			auditor.Opts.Cronjobs.KeyvaultAccessPolicies,
			auditor.auditKeyvaultAccessPolicies,
			func() {
				auditor.prometheus.keyvaultAccessPolicies.Reset()
			},
		)
	}

	if auditor.config.ResourceProviders.IsEnabled() {
		auditor.addCronjob(
			"ResourceProviders",
			auditor.Opts.Cronjobs.ResourceProvider,
			auditor.auditResourceProviders,
			func() {
				auditor.prometheus.resourceProvider.Reset()
			},
		)
	}

	if auditor.config.ResourceProviderFeatures.IsEnabled() {
		auditor.addCronjob(
			"ResourceProviderFeatures",
			auditor.Opts.Cronjobs.ResourceProvider,
			auditor.auditResourceProviderFeatures,
			func() {
				auditor.prometheus.resourceProviderFeature.Reset()
			},
		)
	}

	auditor.cron.Start()
}

func (auditor *AzureAuditor) addCronjob(name string, cronSpec string, callback func(ctx context.Context, subscription *subscriptions.Subscription, callback chan<- func()), resetCallback func()) {
	contextLogger := auditor.logger.WithFields(log.Fields{
		"report": name,
	})
	contextLogger.Infof("scheduling %v audit report cronjob with spec \"%v\"", name, cronSpec)
	_, err := auditor.cron.AddFunc(
		cronSpec,
		func() {
			ctx := context.Background()
			var wg sync.WaitGroup

			startTime := time.Now()
			contextLogger.Infof("starting %v audit report", name)

			metricCallbackChannel := make(chan func())

			go func() {
				subscriptionList := auditor.getSubscriptionList(ctx)
				for _, row := range subscriptionList {
					subscription := row

					wg.Add(1)
					go func(subscription subscriptions.Subscription) {
						defer wg.Done()
						callback(ctx, &subscription, metricCallbackChannel)
					}(subscription)
				}

				wg.Wait()
				close(metricCallbackChannel)
			}()

			// collect metric callbacks
			var metricCallbackList []func()
			for metricCallback := range metricCallbackChannel {
				metricCallbackList = append(metricCallbackList, metricCallback)
			}

			// apply/commit metrics
			resetCallback()
			for _, metricCallback := range metricCallbackList {
				metricCallback()
			}

			reportDuration := time.Since(startTime)
			contextLogger.WithFields(log.Fields{
				"duration": reportDuration.Seconds(),
			}).Infof("finished %v audit report in %s", name, reportDuration.String())
		},
	)

	if err != nil {
		auditor.logger.Panic(err)
	}
}

func (auditor *AzureAuditor) getSubscriptionList(ctx context.Context) (list []subscriptions.Subscription) {
	auditor.locks.subscriptions.Lock()
	defer auditor.locks.subscriptions.Unlock()

	list = []subscriptions.Subscription{}

	if val, ok := auditor.cache.Get("subscriptions"); ok {
		// fetched from cache
		list = val.([]subscriptions.Subscription)
		return
	}

	client := subscriptions.NewClientWithBaseURI(auditor.azure.environment.ResourceManagerEndpoint)
	auditor.decorateAzureClient(&client.Client, auditor.azure.authorizer)

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

func (auditor *AzureAuditor) initCache() {
	auditor.cacheExpiry = 60 * time.Minute
	auditor.cache = cache.New(auditor.cacheExpiry, time.Duration(1*time.Minute))
}

func (auditor *AzureAuditor) initCron() {
	logger := cron.PrintfLogger(auditor.logger)
	auditor.cron = cron.New(cron.WithChain(
		cron.Recover(logger),
	))
}

func (auditor *AzureAuditor) decorateAzureClient(client *autorest.Client, authorizer autorest.Authorizer) {
	client.Authorizer = authorizer
	if err := client.AddToUserAgent(auditor.UserAgent); err != nil {
		auditor.logger.Panic(err)
	}

	azuretracing.DecorateAzureAutoRestClient(client)
}

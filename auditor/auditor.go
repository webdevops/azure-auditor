package auditor

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/to"
	a "github.com/microsoft/kiota-authentication-azure-go"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/patrickmn/go-cache"
	cron "github.com/robfig/cron/v3"
	log "github.com/sirupsen/logrus"

	azureCommon "github.com/webdevops/azure-auditor/azure"

	"github.com/webdevops/azure-auditor/config"
)

const (
	ReportKeyvaultAccessPolicies   = "KeyvaultAccessPolicy"
	ReportResourceProviders        = "ResourceProvider"
	ReportResourceProviderFeatures = "ResourceProviderFeature"
	ReportResourceGroups           = "ResourceGroup"
	ReportRoleAssignments          = "RoleAssignment"
	ReportResourceGraph            = "ResourceGraph:%v"
	ReportLogAnalytics             = "LogAnalytics:%v"
)

type (
	AzureAuditor struct {
		UserAgent string
		Opts      config.Opts

		logger *log.Entry

		config AuditConfig

		azure struct {
			client  *azureCommon.Client
			msGraph *msgraphsdk.GraphServiceClient
		}

		locks struct {
			subscriptions  sync.Mutex
			resourceGroups sync.Mutex
			resources      sync.Mutex
		}

		cron *cron.Cron

		cache       *cache.Cache
		cacheExpiry time.Duration

		report           map[string]*AzureAuditorReport
		reportUncommited map[string]*AzureAuditorReport
		reportLock       *sync.Mutex

		prometheus auditorPrometheus
	}
)

func NewAzureAuditor() *AzureAuditor {
	auditor := AzureAuditor{}
	auditor.logger = log.WithFields(log.Fields{})
	auditor.report = map[string]*AzureAuditorReport{}
	auditor.reportUncommited = map[string]*AzureAuditorReport{}
	auditor.reportLock = &sync.Mutex{}
	return &auditor
}

func (auditor *AzureAuditor) Init() {
	auditor.initAzure()
	auditor.initMsGraph()
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

	if cronspecIsValid(auditor.Opts.Cronjobs.ResourceGroups) && auditor.config.ResourceGroups.IsEnabled() {
		auditor.addCronjobBySubscription(
			ReportResourceGroups,
			auditor.Opts.Cronjobs.ResourceGroups,
			func(ctx context.Context, logger *log.Entry) {
				auditor.config.ResourceGroups.Reset()
			},
			auditor.auditResourceGroups,
			func(ctx context.Context, logger *log.Entry) {
				auditor.prometheus.resourceGroup.Reset()
			},
		)
	}

	if cronspecIsValid(auditor.Opts.Cronjobs.RoleAssignments) && auditor.config.RoleAssignments.IsEnabled() {
		auditor.addCronjobBySubscription(
			ReportRoleAssignments,
			auditor.Opts.Cronjobs.RoleAssignments,
			func(ctx context.Context, logger *log.Entry) {
				auditor.config.RoleAssignments.Reset()
			},
			auditor.auditRoleAssignments,
			func(ctx context.Context, logger *log.Entry) {
				auditor.prometheus.roleAssignment.Reset()
			},
		)
	}

	if cronspecIsValid(auditor.Opts.Cronjobs.KeyvaultAccessPolicies) && auditor.config.KeyvaultAccessPolicies.IsEnabled() {
		auditor.addCronjobBySubscription(
			ReportKeyvaultAccessPolicies,
			auditor.Opts.Cronjobs.KeyvaultAccessPolicies,
			func(ctx context.Context, logger *log.Entry) {
				auditor.config.KeyvaultAccessPolicies.Reset()
			},
			auditor.auditKeyvaultAccessPolicies,
			func(ctx context.Context, logger *log.Entry) {
				auditor.prometheus.keyvaultAccessPolicies.Reset()
			},
		)
	}

	if cronspecIsValid(auditor.Opts.Cronjobs.ResourceProvider) && auditor.config.ResourceProviders.IsEnabled() {
		auditor.addCronjobBySubscription(
			ReportResourceProviders,
			auditor.Opts.Cronjobs.ResourceProvider,
			func(ctx context.Context, logger *log.Entry) {
				auditor.config.ResourceProviders.Reset()
			},
			auditor.auditResourceProviders,
			func(ctx context.Context, logger *log.Entry) {
				auditor.prometheus.resourceProvider.Reset()
			},
		)
	}

	if cronspecIsValid(auditor.Opts.Cronjobs.ResourceProvider) && auditor.config.ResourceProviderFeatures.IsEnabled() {
		auditor.addCronjobBySubscription(
			ReportResourceProviderFeatures,
			auditor.Opts.Cronjobs.ResourceProvider,
			func(ctx context.Context, logger *log.Entry) {
				auditor.config.ResourceProviderFeatures.Reset()
			},
			auditor.auditResourceProviderFeatures,
			func(ctx context.Context, logger *log.Entry) {
				auditor.prometheus.resourceProviderFeature.Reset()
			},
		)
	}

	if cronspecIsValid(auditor.Opts.Cronjobs.ResourceGraph) && auditor.config.ResourceGraph.IsEnabled() {
		for queryName, queryConfig := range auditor.config.ResourceGraph.Queries {
			resourceGraphConfig := queryConfig
			auditor.addCronjobBySubscription(
				fmt.Sprintf(ReportResourceGraph, queryName),
				auditor.Opts.Cronjobs.ResourceGraph,
				func(ctx context.Context, logger *log.Entry) {
					for _, queryConfig := range auditor.config.ResourceGraph.Queries {
						queryConfig.Reset()
					}
				},
				func(ctx context.Context, logger *log.Entry, subscription *armsubscriptions.Subscription, report *AzureAuditorReport, callback chan<- func()) {
					contextLogger := log.WithField("configQueryName", queryName)
					auditor.auditResourceGraph(ctx, contextLogger, subscription, queryName, resourceGraphConfig, report, callback)
				},
				func(ctx context.Context, logger *log.Entry) {
					for _, gauge := range auditor.prometheus.resourceGraph {
						gauge.Reset()
					}
				},
			)
		}
	}

	if cronspecIsValid(auditor.Opts.Cronjobs.LogAnalytics) && auditor.config.LogAnalytics.IsEnabled() {
		for queryName, queryConfig := range auditor.config.LogAnalytics.Queries {
			logAnalyticsConfig := queryConfig
			auditor.addCronjob(
				fmt.Sprintf(ReportLogAnalytics, queryName),
				auditor.Opts.Cronjobs.LogAnalytics,
				func(ctx context.Context, logger *log.Entry) {
					for _, queryConfig := range auditor.config.LogAnalytics.Queries {
						queryConfig.Reset()
					}
				},
				func(ctx context.Context, logger *log.Entry, report *AzureAuditorReport, callback chan<- func()) {
					contextLogger := log.WithField("configQueryName", queryName)
					auditor.auditLogAnalytics(ctx, contextLogger, queryName, logAnalyticsConfig, report, callback)
				},
				func(ctx context.Context, logger *log.Entry) {
					for _, gauge := range auditor.prometheus.logAnalytics {
						gauge.Reset()
					}
				},
			)
		}
	}

	// check if cron jobs are active
	cronjobEntries := auditor.cron.Entries()
	if len(cronjobEntries) == 0 {
		auditor.logger.Error("no cronjobs enabled")
		os.Exit(1)
	}

	// start cron in background
	go func() {
		// run all reports to keep report/metrics up2date
		for _, entry := range cronjobEntries {
			entry.WrappedJob.Run()
		}

		// start cron scheduling
		auditor.cron.Start()
	}()
}

func (auditor *AzureAuditor) addCronjob(name string, cronSpec string, startupCallback func(ctx context.Context, logger *log.Entry), callback func(ctx context.Context, logger *log.Entry, report *AzureAuditorReport, callback chan<- func()), finishCallback func(ctx context.Context, logger *log.Entry)) {
	contextLogger := auditor.logger.WithFields(log.Fields{
		"report": name,
	})
	contextLogger.Infof("scheduling %v audit report cronjob with spec \"%v\"", name, cronSpec)
	_, err := auditor.cron.AddFunc(
		cronSpec,
		func() {
			ctx := context.Background()

			startTime := time.Now()
			contextLogger.Infof("starting %v audit report", name)

			metricCallbackChannel := make(chan func())

			startupCallback(ctx, contextLogger)

			go func() {
				report := auditor.startReport(name)
				callback(ctx, contextLogger, report, metricCallbackChannel)
				close(metricCallbackChannel)
			}()

			// collect metric callbacks
			var metricCallbackList []func()
			for metricCallback := range metricCallbackChannel {
				metricCallbackList = append(metricCallbackList, metricCallback)
			}

			// apply/commit metrics (only if not dry run)
			if !auditor.Opts.DryRun {
				finishCallback(ctx, contextLogger)
				for _, metricCallback := range metricCallbackList {
					metricCallback()
				}
			}

			auditor.commitReport(name)

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

func (auditor *AzureAuditor) addCronjobBySubscription(name string, cronSpec string, startupCallback func(ctx context.Context, logger *log.Entry), callback func(ctx context.Context, logger *log.Entry, subscription *armsubscriptions.Subscription, report *AzureAuditorReport, callback chan<- func()), finishCallback func(ctx context.Context, logger *log.Entry)) {
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

			startupCallback(ctx, contextLogger)

			go func() {
				subscriptionList := auditor.getSubscriptionList(ctx)
				report := auditor.startReport(name)
				for _, row := range subscriptionList {
					subscription := row

					wg.Add(1)
					go func(subscription *armsubscriptions.Subscription) {
						defer wg.Done()
						callLogger := contextLogger.WithFields(log.Fields{
							"subscriptionID":   to.String(subscription.SubscriptionID),
							"subscriptionName": to.String(subscription.DisplayName),
						})
						callback(ctx, callLogger, subscription, report, metricCallbackChannel)
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

			// apply/commit metrics (only if not dry run)
			if !auditor.Opts.DryRun {
				finishCallback(ctx, contextLogger)
				for _, metricCallback := range metricCallbackList {
					metricCallback()
				}
			}

			auditor.commitReport(name)

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

func (auditor *AzureAuditor) initAzure() {
	var err error
	auditor.azure.client, err = azureCommon.NewClientFromEnvironment(*auditor.Opts.Azure.Environment, auditor.logger.Logger)
	if err != nil {
		auditor.logger.Panic(err)
	}
	auditor.azure.client.SetUserAgent(auditor.UserAgent)
	auditor.azure.client.SetSubscriptionFilter(auditor.Opts.Azure.Subscription...)
}

func (auditor *AzureAuditor) initMsGraph() {
	// azure authorizer
	switch strings.ToLower(os.Getenv("AZURE_AUTH")) {
	case "az", "cli", "azcli":
		cred, err := azidentity.NewAzureCLICredential(nil)
		if err != nil {
			auditor.logger.Panic(err)
		}

		auth, err := a.NewAzureIdentityAuthenticationProvider(cred)
		if err != nil {
			auditor.logger.Panic(err)
		}

		adapter, err := msgraphsdk.NewGraphRequestAdapter(auth)
		if err != nil {
			auditor.logger.Panic(err)
		}

		auditor.azure.msGraph = msgraphsdk.NewGraphServiceClient(adapter)
	default:
		cred, err := azidentity.NewEnvironmentCredential(nil)
		if err != nil {
			auditor.logger.Panic(err)
		}

		auth, err := a.NewAzureIdentityAuthenticationProvider(cred)
		if err != nil {
			auditor.logger.Panic(err)
		}

		adapter, err := msgraphsdk.NewGraphRequestAdapter(auth)
		if err != nil {
			auditor.logger.Panic(err)
		}

		auditor.azure.msGraph = msgraphsdk.NewGraphServiceClient(adapter)
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
	auditor.azure.client.DecorateAzureAutorestWithAuthorizer(client, authorizer)
}

func (auditor *AzureAuditor) GetReport() map[string]*AzureAuditorReport {
	return auditor.report
}

func (auditor *AzureAuditor) startReport(name string) *AzureAuditorReport {
	auditor.reportLock.Lock()
	defer auditor.reportLock.Unlock()

	// create empty report if no report
	if _, ok := auditor.report[name]; !ok {
		auditor.report[name] = NewAzureAuditorReport()
	}

	reportTime := time.Now()
	auditor.reportUncommited[name] = NewAzureAuditorReport()
	auditor.reportUncommited[name].UpdateTime = &reportTime
	return auditor.reportUncommited[name]
}

func (auditor *AzureAuditor) commitReport(name string) {
	auditor.reportLock.Lock()
	defer auditor.reportLock.Unlock()

	auditor.report[name] = auditor.reportUncommited[name]
}

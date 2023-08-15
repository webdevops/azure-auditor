package auditor

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/patrickmn/go-cache"
	cron "github.com/robfig/cron/v3"

	"go.uber.org/zap"
	"go.uber.org/zap/zapio"

	"github.com/webdevops/go-common/azuresdk/armclient"
	"github.com/webdevops/go-common/msgraphsdk/msgraphclient"

	"github.com/webdevops/azure-auditor/auditor/validator"
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

		Logger *zap.SugaredLogger

		config AuditConfig

		azure struct {
			client  *armclient.ArmClient
			msGraph *msgraphclient.MsGraphClient
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
		reportLock       *sync.RWMutex

		metricsLock *sync.RWMutex

		prometheus auditorPrometheus
	}
)

func NewAzureAuditor() *AzureAuditor {
	auditor := AzureAuditor{}
	auditor.report = map[string]*AzureAuditorReport{}
	auditor.reportUncommited = map[string]*AzureAuditorReport{}
	auditor.reportLock = &sync.RWMutex{}
	auditor.metricsLock = &sync.RWMutex{}
	return &auditor
}

func (auditor *AzureAuditor) Init() {
	auditor.initAzure()
	auditor.initMsGraph()
	auditor.initPrometheus()
	auditor.initCache()
	auditor.initCron()
	
	validator.Logger = auditor.Logger
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
			func(ctx context.Context, logger *zap.SugaredLogger) {
				auditor.config.ResourceGroups.Reset()
			},
			auditor.auditResourceGroups,
			func(ctx context.Context, logger *zap.SugaredLogger) {
				auditor.prometheus.resourceGroup.Reset()
			},
		)
	}

	if cronspecIsValid(auditor.Opts.Cronjobs.RoleAssignments) && auditor.config.RoleAssignments.IsEnabled() {
		auditor.addCronjobBySubscription(
			ReportRoleAssignments,
			auditor.Opts.Cronjobs.RoleAssignments,
			func(ctx context.Context, logger *zap.SugaredLogger) {
				auditor.config.RoleAssignments.Reset()
			},
			auditor.auditRoleAssignments,
			func(ctx context.Context, logger *zap.SugaredLogger) {
				auditor.prometheus.roleAssignment.Reset()
			},
		)
	}

	if cronspecIsValid(auditor.Opts.Cronjobs.KeyvaultAccessPolicies) && auditor.config.KeyvaultAccessPolicies.IsEnabled() {
		auditor.addCronjobBySubscription(
			ReportKeyvaultAccessPolicies,
			auditor.Opts.Cronjobs.KeyvaultAccessPolicies,
			func(ctx context.Context, logger *zap.SugaredLogger) {
				auditor.config.KeyvaultAccessPolicies.Reset()
			},
			auditor.auditKeyvaultAccessPolicies,
			func(ctx context.Context, logger *zap.SugaredLogger) {
				auditor.prometheus.keyvaultAccessPolicies.Reset()
			},
		)
	}

	if cronspecIsValid(auditor.Opts.Cronjobs.ResourceProvider) && auditor.config.ResourceProviders.IsEnabled() {
		auditor.addCronjobBySubscription(
			ReportResourceProviders,
			auditor.Opts.Cronjobs.ResourceProvider,
			func(ctx context.Context, logger *zap.SugaredLogger) {
				auditor.config.ResourceProviders.Reset()
			},
			auditor.auditResourceProviders,
			func(ctx context.Context, logger *zap.SugaredLogger) {
				auditor.prometheus.resourceProvider.Reset()
			},
		)
	}

	if cronspecIsValid(auditor.Opts.Cronjobs.ResourceProvider) && auditor.config.ResourceProviderFeatures.IsEnabled() {
		auditor.addCronjobBySubscription(
			ReportResourceProviderFeatures,
			auditor.Opts.Cronjobs.ResourceProvider,
			func(ctx context.Context, logger *zap.SugaredLogger) {
				auditor.config.ResourceProviderFeatures.Reset()
			},
			auditor.auditResourceProviderFeatures,
			func(ctx context.Context, logger *zap.SugaredLogger) {
				auditor.prometheus.resourceProviderFeature.Reset()
			},
		)
	}

	if cronspecIsValid(auditor.Opts.Cronjobs.ResourceGraph) && auditor.config.ResourceGraph.IsEnabled() {
		for key, queryConfig := range auditor.config.ResourceGraph.Queries {
			queryName := key
			resourceGraphConfig := queryConfig
			auditor.addCronjobBySubscription(
				fmt.Sprintf(ReportResourceGraph, queryName),
				auditor.Opts.Cronjobs.ResourceGraph,
				func(ctx context.Context, logger *zap.SugaredLogger) {
					auditor.config.ResourceGraph.Queries[queryName].Reset()
				},
				func(ctx context.Context, logger *zap.SugaredLogger, subscription *armsubscriptions.Subscription, report *AzureAuditorReport, callback chan<- func()) {
					contextLogger := logger.With(zap.String("configQueryName", queryName))
					auditor.auditResourceGraph(ctx, contextLogger, subscription, queryName, resourceGraphConfig, report, callback)
				},
				func(ctx context.Context, logger *zap.SugaredLogger) {
					auditor.prometheus.resourceGraph[queryName].Reset()
				},
			)
		}
	}

	if cronspecIsValid(auditor.Opts.Cronjobs.LogAnalytics) && auditor.config.LogAnalytics.IsEnabled() {
		for key, queryConfig := range auditor.config.LogAnalytics.Queries {
			queryName := key
			logAnalyticsConfig := queryConfig
			auditor.addCronjob(
				fmt.Sprintf(ReportLogAnalytics, queryName),
				auditor.Opts.Cronjobs.LogAnalytics,
				func(ctx context.Context, logger *zap.SugaredLogger) {
					auditor.config.LogAnalytics.Queries[queryName].Reset()
				},
				func(ctx context.Context, logger *zap.SugaredLogger, report *AzureAuditorReport, callback chan<- func()) {
					contextLogger := logger.With(zap.String("configQueryName", queryName))
					auditor.auditLogAnalytics(ctx, contextLogger, queryName, logAnalyticsConfig, report, callback)
				},
				func(ctx context.Context, logger *zap.SugaredLogger) {
					auditor.prometheus.logAnalytics[queryName].Reset()
				},
			)
		}
	}

	// check if cron jobs are active
	cronjobEntries := auditor.cron.Entries()
	if len(cronjobEntries) == 0 {
		auditor.Logger.Error("no cronjobs enabled")
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

func (auditor *AzureAuditor) addCronjob(name string, cronSpec string, startupCallback func(ctx context.Context, logger *zap.SugaredLogger), callback func(ctx context.Context, logger *zap.SugaredLogger, report *AzureAuditorReport, callback chan<- func()), finishCallback func(ctx context.Context, logger *zap.SugaredLogger)) {
	contextLogger := auditor.Logger.With(zap.String("report", name))
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
			contextLogger.With(zap.Float64("duration", reportDuration.Seconds())).Infof("finished %v audit report in %s", name, reportDuration.String())
		},
	)

	if err != nil {
		auditor.Logger.Panic(err)
	}
}

func (auditor *AzureAuditor) addCronjobBySubscription(name string, cronSpec string, startupCallback func(ctx context.Context, logger *zap.SugaredLogger), callback func(ctx context.Context, logger *zap.SugaredLogger, subscription *armsubscriptions.Subscription, report *AzureAuditorReport, callback chan<- func()), finishCallback func(ctx context.Context, logger *zap.SugaredLogger)) {
	contextLogger := auditor.Logger.With(zap.String("report", name))
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
						callLogger := contextLogger.With(
							zap.String("subscriptionID", to.String(subscription.SubscriptionID)),
							zap.String("subscriptionName", to.String(subscription.DisplayName)),
						)
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
				auditor.metricsLock.Lock()
				defer auditor.metricsLock.Unlock()
				finishCallback(ctx, contextLogger)
				for _, metricCallback := range metricCallbackList {
					metricCallback()
				}
			}

			auditor.commitReport(name)

			reportDuration := time.Since(startTime)
			contextLogger.With(zap.Float64("duration", reportDuration.Seconds())).Infof("finished %v audit report in %s", name, reportDuration.String())
		},
	)

	if err != nil {
		auditor.Logger.Panic(err)
	}
}

func (auditor *AzureAuditor) initAzure() {
	var err error
	auditor.azure.client, err = armclient.NewArmClientWithCloudName(*auditor.Opts.Azure.Environment, auditor.Logger)
	if err != nil {
		auditor.Logger.Panic(err)
	}
	auditor.azure.client.SetUserAgent(auditor.UserAgent)
	auditor.azure.client.SetSubscriptionFilter(auditor.Opts.Azure.Subscription...)
}

func (auditor *AzureAuditor) initMsGraph() {
	var err error
	auditor.azure.msGraph, err = msgraphclient.NewMsGraphClientWithCloudName(*auditor.Opts.Azure.Environment, *auditor.Opts.Azure.Tenant, auditor.Logger)
	if err != nil {
		auditor.Logger.Panic(err)
	}
	auditor.azure.client.SetUserAgent(auditor.UserAgent)
}

func (auditor *AzureAuditor) initCache() {
	auditor.cacheExpiry = 60 * time.Minute
	auditor.cache = cache.New(auditor.cacheExpiry, time.Duration(1*time.Minute))
}

func (auditor *AzureAuditor) initCron() {
	stdOutWriter := &zapio.Writer{Log: auditor.Logger.Desugar(), Level: zap.InfoLevel}
	logger := cron.PrintfLogger(log.New(stdOutWriter, "cron: ", log.LstdFlags))
	auditor.cron = cron.New(cron.WithChain(
		cron.Recover(logger),
	))
}

func (auditor *AzureAuditor) GetReport() map[string]*AzureAuditorReport {
	auditor.reportLock.RLock()
	defer auditor.reportLock.RUnlock()
	return auditor.report
}

func (auditor *AzureAuditor) ReportLock() *sync.RWMutex {
	return auditor.reportLock
}

func (auditor *AzureAuditor) MetricsLock() *sync.RWMutex {
	return auditor.metricsLock
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

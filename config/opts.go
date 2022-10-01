package config

import (
	"encoding/json"
	"time"

	log "github.com/sirupsen/logrus"
)

type (
	Opts struct {
		// logger
		Logger struct {
			Debug bool `long:"log.debug"    env:"LOG_DEBUG"  description:"debug mode"`
			Trace bool `long:"log.trace"    env:"LOG_TRACE"  description:"trace mode"`
			Json  bool `long:"log.json"     env:"LOG_JSON"   description:"Switch log output to json format"`
		}

		// azure
		Azure struct {
			Environment  *string  `long:"azure.environment"   env:"AZURE_ENVIRONMENT"                     description:"Azure environment name" default:"AZUREPUBLICCLOUD"`
			Tenant       *string  `long:"azure.tenant"        env:"AZURE_TENANT_ID"                       description:"Azure tenant id" required:"true"`
			Subscription []string `long:"azure.subscription"  env:"AZURE_SUBSCRIPTION_ID"  env-delim:" "  description:"Azure subscription ID"`
			InheritTags  []string `long:"azure.tag.inherit"   env:"AZURE_TAG_INHERIT"      env-delim:" "  description:"Inherit tags"`
		}

		// report
		Report struct {
			Title string `long:"report.title"   env:"REPORT_TITLE"                     description:"Report title"`
		}

		// scrape times
		Cronjobs struct {
			KeyvaultAccessPolicies string `long:"cron.keytvaultaccesspolicies" env:"CRON_KEYTVAULTACCESSPOLICIES"  description:"Cronjob for KeyVault AccessPolicies report" default:"0 * * * *"`
			ResourceGroups         string `long:"cron.resourcegroups"          env:"CRON_RESOURCEGROUPS"           description:"Cronjob for ResourceGroups report"          default:"*/30 * * * *"`
			ResourceProvider       string `long:"cron.resourceproviders"       env:"CRON_RESOURCEPROVIDERS"        description:"Cronjob for ResourceProviders report"       default:"0 * * * *"`
			RoleAssignments        string `long:"cron.roleassignments"         env:"CRON_ROLEASSIGNMENTS"          description:"Cronjob for RoleAssignments report"         default:"*/5 * * * *"`
			ResourceGraph          string `long:"cron.resourcegraph"           env:"CRON_RESOURCEGRAPH"            description:"Cronjob for ResourceGraph report"           default:"15 * * * *"`
			LogAnalytics           string `long:"cron.loganalytics"            env:"CRON_LOGANALYTICS"             description:"Cronjob for LogAnalytics report"            default:"30 * * * *"`
		}

		LogAnalytics struct {
			WaitTime time.Duration `long:"loganalytics.waitduration"           env:"LOGANALYTICS_WAITDURATION"     description:"Wait duration between LogAnalytics queries" default:"5s"`
		}

		Config []string `long:"config"   env:"CONFIG" env-delim:":"   description:"Config file path"      required:"true"`
		DryRun bool     `long:"dry-run"  env:"DRYRUN"                 description:"Dry Run (report only)"`

		// general options
		Server struct {
			// general options
			Bind         string        `long:"server.bind"              env:"SERVER_BIND"           description:"Server address"        default:":8080"`
			ReadTimeout  time.Duration `long:"server.timeout.read"      env:"SERVER_TIMEOUT_READ"   description:"Server read timeout"   default:"5s"`
			WriteTimeout time.Duration `long:"server.timeout.write"     env:"SERVER_TIMEOUT_WRITE"  description:"Server write timeout"  default:"10s"`

			PathReport string `long:"server.path.report" env:"SERVER_PATH_REPORT"   description:"Server path for report"     default:"/report"`
		}
	}
)

func (o *Opts) GetJson() []byte {
	jsonBytes, err := json.Marshal(o)
	if err != nil {
		log.Panic(err)
	}
	return jsonBytes
}

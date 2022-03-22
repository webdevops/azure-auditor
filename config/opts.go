package config

import (
	"encoding/json"

	log "github.com/sirupsen/logrus"
)

type (
	Opts struct {
		// logger
		Logger struct {
			Debug   bool `           long:"debug"        env:"DEBUG"    description:"debug mode"`
			Verbose bool `short:"v"  long:"verbose"      env:"VERBOSE"  description:"verbose mode"`
			LogJson bool `           long:"log.json"     env:"LOG_JSON" description:"Switch log output to json format"`
		}

		// azure
		Azure struct {
			Environment  *string  `long:"azure.environment"   env:"AZURE_ENVIRONMENT"                     description:"Azure environment name" default:"AZUREPUBLICCLOUD"`
			Subscription []string `long:"azure.subscription"  env:"AZURE_SUBSCRIPTION_ID"  env-delim:" "  description:"Azure subscription ID"`
		}

		// scrape times
		Cronjobs struct {
			KeyvaultAccessPolicies string `long:"cron.keytvaultaccesspolicies" env:"CRON_KEYTVAULTACCESSPOLICIES"  description:"Cronjob for KeyVault AccessPolicies report" default:"0 * * * *"`
			ResourceGroups         string `long:"cron.resourcegroups"          env:"CRON_RESOURCEGROUPS"           description:"Cronjob for ResourceGroups report"          default:"*/30 * * * *"`
			ResourceProvider       string `long:"cron.resourceproviders"       env:"CRON_RESOURCEPROVIDERS"        description:"Cronjob for ResourceProviders report"       default:"0 * * * *"`
			RoleAssignments        string `long:"cron.roleassignments"         env:"CRON_ROLEASSIGNMENTS"          description:"Cronjob for RoleAssignments report"         default:"*/5 * * * *"`
		}

		Config string `long:"config"  env:"CONFIG"   description:"Config file path"     required:"true"`
		DryRun bool   `long:"dry-run"  env:"DRYRUN"  description:"Dry Run (report only)"`

		// general options
		ServerBind string `long:"bind" env:"SERVER_BIND"   description:"Server address"     default:":8080"`
	}
)

func (o *Opts) GetJson() []byte {
	jsonBytes, err := json.Marshal(o)
	if err != nil {
		log.Panic(err)
	}
	return jsonBytes
}

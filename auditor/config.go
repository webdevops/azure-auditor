package auditor

import (
	"fmt"
	"github.com/gofrs/uuid"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"io/ioutil"
)

type (
	AuditConfig struct {
		RoleAssignments          *AuditConfigRoleAssignments          `yaml:"roleAssignments"`
		ResourceGroups           *AuditConfigResourceGroups           `yaml:"resourceGroups"`
		ResourceProviders        *AuditConfigResourceProviders        `yaml:"resourceProviders"`
		ResourceProviderFeatures *AuditConfigResourceProviderFeatures `yaml:"resourceProviderFeatures"`
		KeyvaultAccessPolicies   *AuditConfigKeyvaultAccessPolicies   `yaml:"keyvaultAccessPolicies"`
	}

	AuditConfigBaseRule struct {
		RuleID string `yaml:"rule"`
	}
)

var (
	RuleIdCounter = 0
)

func (auditor *AzureAuditor) ParseConfig(path string) {
	var configRaw []byte

	auditor.config = AuditConfig{}

	auditor.logger.Infof("reading configuration from file %v", path)
	/* #nosec */
	if data, err := ioutil.ReadFile(path); err == nil {
		configRaw = data
	} else {
		auditor.logger.Panic(err)
	}

	log.WithField("path", path).Info("parsing configuration")
	if err := yaml.Unmarshal(configRaw, &auditor.config); err != nil {
		auditor.logger.Panic(err)
	}
}

func (rule *AuditConfigBaseRule) handleRuleStatus(object *AzureBaseObject, status bool) bool {
	log.WithFields(log.Fields{
		"resourceID":       object.ResourceID,
		"rule":             rule.id(),
		"validationStatus": status,
	}).Debugf("validation status: \"%v\"", status)
	return status
}

func (rule *AuditConfigBaseRule) id() string {
	if rule.RuleID == "" {
		if val, err := uuid.NewV4(); err == nil {
			rule.RuleID = fmt.Sprintf("<rule:%v>", val)
		} else {
			log.Panic(err)
		}
	}

	return rule.RuleID
}

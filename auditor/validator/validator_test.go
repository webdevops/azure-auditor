package validator

import (
	"testing"
	"time"

	"sigs.k8s.io/yaml"
)

type (
	TestValidator struct {
		Test *AuditConfigValidation `yaml:"test"`
	}
)

func TestValidation(t *testing.T) {
	var obj *AzureObject
	yamlConfig := `

test:
  enabled: true
  rules:
    - rule: tags
      resourcegroup.tag.foobar:
        required: true
        regexp: "^barfoo"
      action: continue

    - rule: ignoretest
      resourcegroup.name: barfoo
      action: ignore

    - rule: name
      resourcegroup.name: foobar
      action: allow

`

	config := TestValidator{}
	if err := yaml.Unmarshal([]byte(yamlConfig), &config); err != nil {
		t.Error(err)
		return
	}

	obj = NewAzureObject(
		map[string]interface{}{
			"resourcegroup.name":       "foobar",
			"resourcegroup.tag.foobar": "barfoo",
		},
	)
	if _, status := config.Test.Validate(obj); !status.IsAllow() {
		t.Errorf("expected matching object, got: %v", status)
	}

	obj = NewAzureObject(
		map[string]interface{}{
			"resourcegroup.name":       "foobar",
			"resourcegroup.tag.barfoo": "foobar",
		},
	)
	if _, status := config.Test.Validate(obj); !status.IsDeny() {
		t.Errorf("expected NOT matching object, got: %v", status)
	}

	obj = NewAzureObject(
		map[string]interface{}{
			"resourcegroup.name":       "barfoo",
			"resourcegroup.tag.foobar": "barfoo",
		},
	)
	if _, status := config.Test.Validate(obj); !status.IsIgnore() {
		t.Errorf("expected NOT matching object, got: %v", status)
	}
}

func TestStringList(t *testing.T) {
	list := []string{"foo", "bar", "baz"}

	// ALLOF
	if status := stringListIsMatchingAllOf(list, []string{"foo", "bar", "baz"}); !status {
		t.Errorf("expected matching, got: %v", status)
	}

	if status := stringListIsMatchingAllOf(list, []string{"foo", "bar"}); status {
		t.Errorf("expected NOT matching, got: %v", status)
	}

	if status := stringListIsMatchingAllOf(list, []string{"foo2", "foobar", "baz"}); status {
		t.Errorf("expected NOT matching, got: %v", status)
	}

	// ANYOF
	if status := stringListIsMatchingAnyOf(list, []string{"bar"}); !status {
		t.Errorf("expected matching, got: %v", status)
	}

	if status := stringListIsMatchingAnyOf(list, []string{"foobar"}); status {
		t.Errorf("expected NOT matching, got: %v", status)
	}

	if status := stringListIsMatchingAnyOf(list, []string{"foo2", "foobar", "baz"}); !status {
		t.Errorf("expected matching, got: %v", status)
	}
}

func TestValidationList(t *testing.T) {
	var obj *AzureObject
	yamlConfig := `

test:
  enabled: true
  rules:
      - rule: deny
        permissions.certificates: { anyof: [all, get, delete, create, import, update, managecontacts, getissuers, setissuers, deleteissuers, manageissuers, recover, backup, restore, purge], required: false }
        permissions.keys: { anyof: [all, decrypt, encrypt, unwrapKey, wrapKey, verify, sign, get, update, create, import, delete, backup, restore, recover, purge], required: false }
        permissions.secrets: { anyof: [all, get, set, delete, backup, restore, recover, purge], required: false }
        permissions.storage: { anyof: [all, get, delete, set, update, regeneratekey, getsas, deletesas, setsas, recover, backup, restore, purge], required: false }
        principal.type: group
        action: deny
      - rule: allow
        principal.type: group
        action: allow
`

	config := TestValidator{}
	if err := yaml.Unmarshal([]byte(yamlConfig), &config); err != nil {
		t.Error(err)
		return
	}

	obj = NewAzureObject(
		map[string]interface{}{
			"permissions.certificates": []string{"list"},
			"permissions.keys":         []string{"list"},
			"permissions.secrets":      []string{"list"},
			"principal.type":           "group",
		},
	)
	if ruleId, status := config.Test.Validate(obj); !status.IsAllow() {
		t.Errorf("expected matching object, got: %v by rule %v", status, ruleId)
	}

	obj = NewAzureObject(
		map[string]interface{}{
			"permissions.certificates": []string{"get", "create", "import", "list", "update"},
			"permissions.keys":         []string{"get", "create", "import", "list", "update"},
			"permissions.secrets":      []string{"get", "set", "list"},
			"principal.type":           "group",
		},
	)
	if ruleId, status := config.Test.Validate(obj); !status.IsDeny() {
		t.Errorf("expected NOT matching object, got: %v by rule %v", status, ruleId)
	}

}

func TestValidationListNot(t *testing.T) {
	var obj *AzureObject
	yamlConfig := `

test:
  enabled: true
  rules:
      - rule: deny
        permissions.certificates: { not: true, allof: [list, listissuers], required: false }
        permissions.keys: { not: true, allof: [list], required: false }
        permissions.secrets: { not: true, allof: [list], required: false }
        permissions.storage: { not: true, allof: [list, listsas], required: false }
        principal.type: group
        action: deny
      - rule: allow
        principal.type: group
        action: allow
`

	config := TestValidator{}
	if err := yaml.Unmarshal([]byte(yamlConfig), &config); err != nil {
		t.Error(err)
		return
	}

	obj = NewAzureObject(
		map[string]interface{}{
			"permissions.certificates": []string{"list"},
			"permissions.keys":         []string{"list"},
			"permissions.secrets":      []string{"list"},
			"principal.type":           "group",
		},
	)
	if ruleId, status := config.Test.Validate(obj); !status.IsAllow() {
		t.Errorf("expected matching object, got: %v by rule %v", status, ruleId)
	}

	obj = NewAzureObject(
		map[string]interface{}{
			"permissions.certificates": []string{"get", "create", "import", "list", "update"},
			"permissions.keys":         []string{"get", "create", "import", "list", "update"},
			"permissions.secrets":      []string{"get", "set", "list"},
			"principal.type":           "group",
		},
	)
	if ruleId, status := config.Test.Validate(obj); !status.IsDeny() || ruleId != "deny" {
		t.Errorf("expected NOT matching object with rule deny, got: %v by rule %v", status, ruleId)
	}

}

func TestValidationParseAs(t *testing.T) {
	var obj *AzureObject
	yamlConfig := `

test:
  enabled: true
  rules:
      - rule: deny
        resourcegroup.tag.updated: { parseAs: "timesince", minDuration: "96h" }
        action: deny
      - rule: allow
`

	config := TestValidator{}
	if err := yaml.Unmarshal([]byte(yamlConfig), &config); err != nil {
		t.Error(err)
		return
	}

	obj = NewAzureObject(
		map[string]interface{}{
			"resourcegroup.tag.updated": time.Now().Format("YYYY-MM-DD"),
		},
	)
	if ruleId, status := config.Test.Validate(obj); !status.IsAllow() {
		t.Errorf("expected matching object, got: %v by rule %v", status, ruleId)
	}

	obj = NewAzureObject(
		map[string]interface{}{
			"resourcegroup.tag.updated": "2000-01-01",
		},
	)
	if ruleId, status := config.Test.Validate(obj); !status.IsDeny() || ruleId != "deny" {
		t.Errorf("expected NOT matching object with rule deny, got: %v by rule %v", status, ruleId)
	}

}

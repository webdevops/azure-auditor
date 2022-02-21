# Azure Audit exporter

[![license](https://img.shields.io/github/license/webdevops/azure-audit-exporter.svg)](https://github.com/webdevops/azure-audit-exporter/blob/master/LICENSE)
[![DockerHub](https://img.shields.io/badge/DockerHub-webdevops%2Fazure--audit--exporter-blue)](https://hub.docker.com/r/webdevops/azure-audit-exporter/)
[![Quay.io](https://img.shields.io/badge/Quay.io-webdevops%2Fazure--audit--exporter-blue)](https://quay.io/repository/webdevops/azure-audit-exporter)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/azure-audit-exporter)](https://artifacthub.io/packages/search?repo=azure-audit-exporter)

Prometheus exporter for Azure Audit reporting

Audit reports:
- ResourceGroups
- RoleAssignments
- ResourceProviders
- ResourceProviderFeatures
- Keyvault AccessPolicies

## Usage

```
Usage:
  azure-audit-exporter [OPTIONS]

Application Options:
      --debug                         debug mode [$DEBUG]
  -v, --verbose                       verbose mode [$VERBOSE]
      --log.json                      Switch log output to json format [$LOG_JSON]
      --azure.environment=            Azure environment name (default: AZUREPUBLICCLOUD) [$AZURE_ENVIRONMENT]
      --azure.subscription=           Azure subscription ID [$AZURE_SUBSCRIPTION_ID]
      --cron.keytvaultaccesspolicies= Cronjob for KeyVault AccessPolicies report (default: 0 * * * *) [$CRON_KEYTVAULTACCESSPOLICIES]
      --cron.resourcegroups=          Cronjob for ResourceGroups report (default: */30 * * * *) [$CRON_RESOURCEGROUPS]
      --cron.resourceproviders=       Cronjob for ResourceProviders report (default: 0 * * * *) [$CRON_RESOURCEPROVIDERS]
      --cron.roleassignments=         Cronjob for RoleAssignments report (default: */5 * * * *) [$CRON_ROLEASSIGNMENTS]
      --config=                       Config file path [$CONFIG]
      --bind=                         Server address (default: :8080) [$SERVER_BIND]

Help Options:
  -h, --help                          Show this help message
```

for Azure API authentication (using ENV vars) see https://docs.microsoft.com/en-us/azure/developer/go/azure-sdk-authentication

## Configuration file

see (example.yaml)[/example.yaml] as for example audit rules

## Metrics

| Metric                                            | Description                        |
|---------------------------------------------------|------------------------------------|
| `azurerm_audit_violation_roleassignment`          | RoleAssingment violations          |
| `azurerm_audit_violation_resourcegroup`           | ResourceGroup violations           |
| `azurerm_audit_violation_resourceprovider`        | ResourceProvider violations        |
| `azurerm_audit_violation_resourceproviderfeature` | ResourceProviderFeature violations |
| `azurerm_audit_violation_keyvault_accesspolicy`   | Keyvault AccessPolicy violations   |

## AzureTracing metrics

(with 22.2.0 and later)

Azuretracing metrics collects latency and latency from azure-sdk-for-go and creates metrics and is controllable using
environment variables (eg. setting buckets, disabling metrics or disable autoreset).

| Metric                                   | Description                                                                            |
|------------------------------------------|----------------------------------------------------------------------------------------|
| `azurerm_api_ratelimit`                  | Azure ratelimit metrics (only on /metrics, resets after query due to limited validity) |
| `azurerm_api_request_*`                  | Azure request count and latency as histogram                                           |

### Settings

| Environment variable                     | Example                            | Description                                                    |
|------------------------------------------|------------------------------------|----------------------------------------------------------------|
| `METRIC_AZURERM_API_REQUEST_BUCKETS`     | `1, 2.5, 5, 10, 30, 60, 90, 120`   | Sets buckets for `azurerm_api_request` histogram metric        |
| `METRIC_AZURERM_API_REQUEST_ENABLE`      | `false`                            | Enables/disables `azurerm_api_request_*` metric                |
| `METRIC_AZURERM_API_REQUEST_LABELS`      | `apiEndpoint, method, statusCode`  | Controls labels of `azurerm_api_request_*` metric              |
| `METRIC_AZURERM_API_RATELIMIT_ENABLE`    | `false`                            | Enables/disables `azurerm_api_ratelimit` metric                |
| `METRIC_AZURERM_API_RATELIMIT_AUTORESET` | `false`                            | Enables/disables `azurerm_api_ratelimit` autoreset after fetch |


| `azurerm_api_request` label | Status             | Description                                                                                              |
|-----------------------------|--------------------|----------------------------------------------------------------------------------------------------------|
| `apiEndpoint`               | enabled by default | hostname of endpoint (max 3 parts)                                                                       |
| `routingRegion`             | enabled by default | detected region for API call, either routing region from Azure Management API or Azure resource location |
| `subscriptionID`            | enabled by default | detected subscriptionID                                                                                  |
| `tenantID`                  | enabled by default | detected tenantID (extracted from jwt auth token)                                                        |
| `resourceProvider`          | enabled by default | detected Azure Management API provider                                                                   |
| `method`                    | enabled by default | HTTP method                                                                                              |
| `statusCode`                | enabled by default | HTTP status code                                                                                         |

## Endpoints

| Metric     | Description                               |
|------------|-------------------------------------------|
| `/metrics` | Prometheus metrics incl. audit violations |
| `/config`  | Parsed and processes config file          |
| `/report`  | Audit report ui                           |
| `/healthz` | Healthz endpoint                          |

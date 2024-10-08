# Azure Auditor

[![license](https://img.shields.io/github/license/webdevops/azure-auditor.svg)](https://github.com/webdevops/azure-auditor/blob/master/LICENSE)
[![DockerHub](https://img.shields.io/badge/DockerHub-webdevops%2Fazure--auditor-blue)](https://hub.docker.com/r/webdevops/azure-auditor/)
[![Quay.io](https://img.shields.io/badge/Quay.io-webdevops%2Fazure--auditor-blue)](https://quay.io/repository/webdevops/azure-auditor)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/azure-auditor)](https://artifacthub.io/packages/search?repo=azure-auditor)

Auditor for Azure resources and settings with Prometheus metrics (violations) for alerting

Audit reports:

- ResourceGroups
- RoleAssignments
- ResourceProviders
- ResourceProviderFeatures
- Keyvault AccessPolicies
- ResourceGraph queries

## Usage

```
Usage:
  azure-auditor [OPTIONS]

Application Options:
      --log.debug                                   debug mode [$LOG_DEBUG]
      --log.devel                                   development mode [$LOG_DEVEL]
      --log.json                                    Switch log output to json format [$LOG_JSON]
      --azure.environment=                          Azure environment name (default: AZUREPUBLICCLOUD) [$AZURE_ENVIRONMENT]
      --azure.tenant=                               Azure tenant id [$AZURE_TENANT_ID]
      --azure.subscription=                         Azure subscription ID [$AZURE_SUBSCRIPTION_ID]
      --azure.tag.inherit=                          Inherit tags [$AZURE_TAG_INHERIT]
      --report.title=                               Report title [$REPORT_TITLE]
      --report.pagination.size=[5|10|25|50|100|250] Report pagination size (default: 50) [$REPORT_PAGINATION_SIZE]
      --cron.keytvaultaccesspolicies=               Cronjob for KeyVault AccessPolicies report (default: 0 * * * *)
                                                    [$CRON_KEYTVAULTACCESSPOLICIES]
      --cron.resourcegroups=                        Cronjob for ResourceGroups report (default: */30 * * * *) [$CRON_RESOURCEGROUPS]
      --cron.resourceproviders=                     Cronjob for ResourceProviders report (default: 0 * * * *) [$CRON_RESOURCEPROVIDERS]
      --cron.roleassignments=                       Cronjob for RoleAssignments report (default: */5 * * * *) [$CRON_ROLEASSIGNMENTS]
      --cron.resourcegraph=                         Cronjob for ResourceGraph report (default: 15 * * * *) [$CRON_RESOURCEGRAPH]
      --cron.loganalytics=                          Cronjob for LogAnalytics report (default: 30 * * * *) [$CRON_LOGANALYTICS]
      --loganalytics.waitduration=                  Wait duration between LogAnalytics queries (default: 5s) [$LOGANALYTICS_WAITDURATION]
      --config=                                     Config file path [$CONFIG]
      --dry-run                                     Dry Run (report only) [$DRYRUN]
      --server.bind=                                Server address (default: :8080) [$SERVER_BIND]
      --server.timeout.read=                        Server read timeout (default: 5s) [$SERVER_TIMEOUT_READ]
      --server.timeout.write=                       Server write timeout (default: 10s) [$SERVER_TIMEOUT_WRITE]
      --server.path.report=                         Server path for report [$SERVER_PATH_REPORT]

Help Options:
  -h, --help                                        Show this help message
```

crons can be disabled by setting them to empty string or `false`

for Azure API authentication (using ENV vars)
see https://docs.microsoft.com/en-us/azure/developer/go/azure-sdk-authentication

For AzureCLI authentication set `AZURE_AUTH=az`

## Configuration file

see (example.yaml)[/example.yaml] as for example audit rules

## Metrics

| Metric                                            | Description                        |
|---------------------------------------------------|------------------------------------|
| `azurerm_audit_violation_roleassignment`          | RoleAssingment violations          |
| `azurerm_audit_violation_resourcegroup`           | ResourceGroup violations           |
| `azurerm_audit_violation_resourceprovider`        | ResourceProvider violations        |
| `azurerm_audit_violation_resourceproviderfeature` | ResourceProviderFeature violations |
| `azurerm_audit_violation_keyvaultaccesspolicy`    | Keyvault AccessPolicy violations   |
| `azurerm_audit_violation_resourcegraph_XXX`       | ResourceGraph violations           |

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

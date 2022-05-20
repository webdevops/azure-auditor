package auditor

import (
	"context"
	"strings"

	"github.com/Azure/go-autorest/autorest/to"
	jsonserialization "github.com/microsoft/kiota/serialization/go/json"
	"github.com/microsoftgraph/msgraph-sdk-go/directoryobjects/getbyids"
)

type (
	MsGraphDirectoryObjectInfo struct {
		Type                 string
		ServicePrincipalType string
		ManagedIdentity      string
		DisplayName          string
		ObjectId             string
		ApplicationId        string
	}
)

func (auditor *AzureAuditor) lookupPrincipalIdMap(ctx context.Context, principalObjectIDMap *map[string]*MsGraphDirectoryObjectInfo) {
	// inject cached entries
	for objectId, row := range *principalObjectIDMap {
		if row == nil {
			if val, ok := auditor.cache.Get("msgraph:" + objectId); ok {
				if directoryObjectInfo, ok := val.(*MsGraphDirectoryObjectInfo); ok {
					(*principalObjectIDMap)[objectId] = directoryObjectInfo
				}
			}
		}
	}

	// build list of not cached entries
	lookupPrincipalObjectIDList := []string{}
	for PrincipalObjectID, directoryObjectInfo := range *principalObjectIDMap {
		if directoryObjectInfo == nil {
			lookupPrincipalObjectIDList = append(lookupPrincipalObjectIDList, PrincipalObjectID)
		}
	}

	// azure limits objects ids
	chunkSize := 999
	for i := 0; i < len(lookupPrincipalObjectIDList); i += chunkSize {
		end := i + chunkSize
		if end > len(lookupPrincipalObjectIDList) {
			end = len(lookupPrincipalObjectIDList)
		}

		principalObjectIDChunkList := lookupPrincipalObjectIDList[i:end]

		opts := getbyids.GetByIdsPostRequestBody{}
		opts.SetIds(principalObjectIDChunkList)

		result, err := auditor.azure.msGraph.DirectoryObjects().GetByIds().Post(&opts)
		if err != nil {
			auditor.logger.Panic(err)
		}

		for _, row := range result.GetValue() {
			objectId := to.String(row.GetId())
			objectData := row.GetAdditionalData()

			objectType := ""
			if val, exists := objectData["@odata.type"]; exists {
				objectType = to.String(val.(*string))
				objectType = strings.ToLower(strings.TrimPrefix(objectType, "#microsoft.graph."))
			}

			servicePrincipalType := ""
			if val, exists := objectData["servicePrincipalType"]; exists {
				servicePrincipalType = to.String(val.(*string))
			}

			displayName := ""
			if val, exists := objectData["displayName"]; exists {
				displayName = to.String(val.(*string))
			}

			applicationId := ""
			if val, exists := objectData["appId"]; exists {
				applicationId = to.String(val.(*string))
			}

			managedIdentity := ""
			if strings.EqualFold(servicePrincipalType, "ManagedIdentity") {
				if alternativeNames, ok := objectData["alternativeNames"].([]*jsonserialization.JsonParseNode); ok {
					if len(alternativeNames) >= 2 {
						if val, err := alternativeNames[1].GetStringValue(); err == nil {
							managedIdentity = to.String(val)
						}
					}
				}
			}

			(*principalObjectIDMap)[objectId] = &MsGraphDirectoryObjectInfo{
				ObjectId:             objectId,
				ApplicationId:        applicationId,
				Type:                 objectType,
				ServicePrincipalType: servicePrincipalType,
				ManagedIdentity:      managedIdentity,
				DisplayName:          displayName,
			}

			// store in cache
			auditor.cache.Set("msgraph:"+objectId, (*principalObjectIDMap)[objectId], auditor.cacheExpiry)
		}
	}
}

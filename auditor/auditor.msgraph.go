package auditor

import (
	"context"
	"strings"

	"github.com/Azure/go-autorest/autorest/to"
	jsonserialization "github.com/microsoft/kiota/serialization/go/json"
	"github.com/microsoftgraph/msgraph-sdk-go/directoryobjects/getbyids"
	"github.com/webdevops/azure-auditor/auditor/validator"
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

func (aadobj *MsGraphDirectoryObjectInfo) AddToAzureObject(row *validator.AzureObject) *validator.AzureObject {
	(*row)["principal.displayName"] = aadobj.DisplayName
	(*row)["principal.applicationID"] = aadobj.ApplicationId
	(*row)["principal.objectID"] = aadobj.ObjectId
	(*row)["principal.type"] = aadobj.Type

	if aadobj.ServicePrincipalType != "" {
		(*row)["principal.serviceprincipaltype"] = aadobj.ServicePrincipalType
	}

	if aadobj.ManagedIdentity != "" {
		(*row)["principal.managedidentity"] = aadobj.ManagedIdentity
	}

	return row
}

func (auditor *AzureAuditor) enrichWithMsGraphPrincipals(ctx context.Context, list *[]*validator.AzureObject) {
	principalObjectIDMap := map[string]*MsGraphDirectoryObjectInfo{}
	for _, row := range *list {
		if principalObjectID, ok := (*row)["principal.objectID"].(string); ok && principalObjectID != "" {
			principalObjectIDMap[principalObjectID] = nil
		}
	}

	auditor.lookupPrincipalIdMap(ctx, &principalObjectIDMap)

	for key, row := range *list {
		(*(*list)[key])["principal.type"] = "unknown"
		if principalObjectID, ok := (*row)["principal.objectID"].(string); ok && principalObjectID != "" {
			if directoryObjectInfo, exists := principalObjectIDMap[principalObjectID]; exists && directoryObjectInfo != nil {
				(*list)[key] = directoryObjectInfo.AddToAzureObject((*list)[key])
			}
		}
	}
}

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

		opts := getbyids.GetByIdsRequestBuilderPostOptions{
			Body: getbyids.NewGetByIdsRequestBody(),
		}
		opts.Body.SetIds(principalObjectIDChunkList)

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

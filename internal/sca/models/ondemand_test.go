package models

import (
	"encoding/json"
	"testing"
)

func TestOnDemandResource_JSONRoundtrip(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want OnDemandResource
	}{
		{
			name: "azure_ad GUID resource_id",
			raw: `{
				"resource_id": "62e90394-69f5-4237-9190-012177145e10",
				"resource_name": "Global Administrator",
				"provider": "azure_ad",
				"custom": false,
				"role_type": 0
			}`,
			want: OnDemandResource{
				ResourceID:   "62e90394-69f5-4237-9190-012177145e10",
				ResourceName: "Global Administrator",
				Provider:     "azure_ad",
				Custom:       false,
				RoleType:     0,
			},
		},
		{
			name: "aws ARN resource_id",
			raw: `{
				"resource_id": "arn:aws:iam::547375531250:role/AdministratorAccess",
				"resource_name": "AdministratorAccess",
				"provider": "aws",
				"custom": false,
				"description": "Admin role",
				"role_type": 1
			}`,
			want: OnDemandResource{
				ResourceID:   "arn:aws:iam::547375531250:role/AdministratorAccess",
				ResourceName: "AdministratorAccess",
				Provider:     "aws",
				Custom:       false,
				Description:  "Admin role",
				RoleType:     1,
			},
		},
		{
			name: "azure_resource custom scoped role",
			raw: `{
				"resource_id": "/providers/Microsoft.Authorization/roleDefinitions/09600ded-d1e9-4c99-a3da-704f2df23384",
				"resource_name": "CyberArk-SIA-Role",
				"provider": "azure_resource",
				"custom": true,
				"assignable_scope": ["/providers/Microsoft.Management/managementGroups/abc"]
			}`,
			want: OnDemandResource{
				ResourceID:      "/providers/Microsoft.Authorization/roleDefinitions/09600ded-d1e9-4c99-a3da-704f2df23384",
				ResourceName:    "CyberArk-SIA-Role",
				Provider:        "azure_resource",
				Custom:          true,
				AssignableScope: []string{"/providers/Microsoft.Management/managementGroups/abc"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got OnDemandResource
			if err := json.Unmarshal([]byte(tt.raw), &got); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			if got.ResourceID != tt.want.ResourceID {
				t.Errorf("ResourceID: got %q want %q", got.ResourceID, tt.want.ResourceID)
			}
			if got.ResourceName != tt.want.ResourceName {
				t.Errorf("ResourceName: got %q want %q", got.ResourceName, tt.want.ResourceName)
			}
			if got.Provider != tt.want.Provider {
				t.Errorf("Provider: got %q want %q", got.Provider, tt.want.Provider)
			}
			if got.Custom != tt.want.Custom {
				t.Errorf("Custom: got %v want %v", got.Custom, tt.want.Custom)
			}
		})
	}
}
